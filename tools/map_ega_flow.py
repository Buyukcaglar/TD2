"""Reproducible direct-flow discovery; unresolved indirect edges remain open.

Consumes only the admitted private, unrelocated EGA image. No game execution.
This is a candidate ledger, never a substitute for instruction contract review.
"""
from __future__ import annotations

import argparse
from collections import deque
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'analysis/tools/python'))
from capstone import Cs, CS_ARCH_X86, CS_MODE_16, CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, CS_GRP_IRET
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

IMAGE = 'analysis/derived/td2ega-v1/TD2EGA.image.bin'
SHA = '8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4'


def address(pair):
    return f'{pair[0]:04X}:{pair[1]:04X}'


def discover(image, roots, resolutions=None):
    resolutions = resolutions or {}
    md = Cs(CS_ARCH_X86, CS_MODE_16)
    md.detail = True
    pending = deque(roots)
    functions = {}
    decoded = {}
    while pending:
        entry = pending.popleft()
        if entry in functions:
            continue
        row = {'entry': address(entry), 'module_offset': entry[0]*16+entry[1],
               'instructions': [], 'calls': [], 'indirect': [], 'exits': [], 'issues': []}
        functions[entry] = row
        work = deque([entry[1]])
        seen = set()
        while work:
            ip = work.popleft()
            pair = (entry[0], ip)
            if ip in seen:
                continue
            seen.add(ip)
            linear = entry[0]*16+ip
            if not 0 <= linear < len(image):
                row['issues'].append({'at': address(pair), 'kind': 'outside_initialized_image'})
                continue
            ins = next(md.disasm(image[linear:linear+min(15, 65536-ip)], ip, count=1), None)
            if ins is None:
                row['issues'].append({'at': address(pair), 'kind': 'undecodable'})
                continue
            decoded[pair] = ins
            row['instructions'].append(ip)
            following = (ip+ins.size) & 65535
            is_call = ins.group(CS_GRP_CALL)
            is_jump = ins.group(CS_GRP_JUMP)
            if is_call or is_jump:
                far = ins.mnemonic in ('lcall', 'ljmp')
                imm = [op.imm for op in ins.operands if op.type == X86_OP_IMM]
                target = None
                if far and len(imm) == 2:
                    target = (imm[0] & 65535, imm[1] & 65535)
                elif not far and len(imm) == 1:
                    target = (entry[0], imm[0] & 65535)
                edge = {'site': address(pair), 'kind': ins.mnemonic, 'size': ins.size}
                if target is not None:
                    edge['target'] = address(target)
                    if is_call:
                        row['calls'].append(edge)
                        pending.append(target)
                    elif target[0] != entry[0]:
                        row['exits'].append(edge)
                        pending.append(target)
                    else:
                        work.append(target[1])
                else:
                    edge['operand'] = ins.op_str
                    resolution = resolutions.get(address(pair))
                    if resolution:
                        edge['review'] = resolution
                        for destination in resolution.get('targets', []):
                            resolved = tuple(int(v,16) for v in destination.split(':'))
                            if is_call or resolved[0] != entry[0]:
                                pending.append(resolved)
                            elif resolution.get('disposition') != 'saved_far_return':
                                work.append(resolved[1])
                    row['indirect'].append(edge)
                if is_call or ins.mnemonic not in ('jmp', 'ljmp'):
                    work.append(following)
            elif ins.group(CS_GRP_RET) or ins.group(CS_GRP_IRET) or ins.mnemonic in ('hlt', 'ud2'):
                row['exits'].append({'site': address(pair), 'kind': ins.mnemonic,
                                     'stack_immediate': ins.op_str})
            elif ins.mnemonic == 'int' and ins.operands[0].imm == 0x20:
                row['exits'].append({'site': address(pair), 'kind': 'int20'})
            else:
                work.append(following)
            if len(seen) > 65536:
                raise RuntimeError('Instruction bound exceeded')
        row['instructions'].sort()
    return functions, decoded


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--revision', required=True)
    ap.add_argument('--root', action='append', default=[])
    ap.add_argument('--resolutions', type=Path)
    args = ap.parse_args()
    if not args.revision.replace('-', '').isalnum():
        raise ValueError('Invalid revision')
    image = (ROOT / IMAGE).read_bytes()
    if hashlib.sha256(image).hexdigest() != SHA:
        raise ValueError('Unadmitted image')
    roots = [(0x13a8, 0x3f8)] + [tuple(int(v, 16) for v in r.split(':')) for r in args.root]
    review = json.loads(args.resolutions.read_text()) if args.resolutions else {}
    roots += [tuple(int(v,16) for v in r['entry'].split(':')) for r in review.get('additional_roots',[])]
    functions, decoded = discover(image, roots, review.get('sites',{}))
    out = ROOT / 'analysis/flow' / args.revision
    out.mkdir(parents=True, exist_ok=False)
    instructions = []
    memory = []
    platform = []
    byte_owners = {}
    for pair, ins in sorted(decoded.items()):
        linear = pair[0]*16+pair[1]
        instructions.append(f'{address(pair)} [{linear:05X}] {ins.bytes.hex():<30} {ins.mnemonic} {ins.op_str}')
        for byte in range(linear, linear+ins.size):
            byte_owners.setdefault(byte, set()).add(linear)
        for op in ins.operands:
            if op.type == X86_OP_MEM:
                memory.append({'site': address(pair), 'mnemonic': ins.mnemonic,
                               'segment': ins.reg_name(op.mem.segment), 'base': ins.reg_name(op.mem.base),
                               'index': ins.reg_name(op.mem.index), 'displacement': op.mem.disp,
                               'width': op.size, 'access': op.access})
        if ins.mnemonic in ('int', 'in', 'out', 'insb', 'insw', 'outsb', 'outsw', 'cli', 'sti', 'iret'):
            platform.append({'site': address(pair), 'mnemonic': ins.mnemonic, 'operand': ins.op_str})
    overlap = [x for x, owners in byte_owners.items() if len(owners) > 1]
    result = {'schema': 1, 'image': IMAGE, 'image_sha256': SHA,
              'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'resolutions_sha256': hashlib.sha256(args.resolutions.read_bytes()).hexdigest() if args.resolutions else None,
              'method': 'Capstone16 recursive direct branches/calls from explicit roots; call fallthrough conservatively retained',
              'roots': [address(x) for x in roots], 'function_candidates': len(functions),
              'instruction_count': len(decoded), 'instruction_bytes': len(byte_owners),
              'overlap_byte_count': len(overlap), 'overlap_module_offsets': overlap,
              'limits': ['No dynamic execution or semantic contract admission',
                         'Indirect targets and interrupt installation need manual recovery',
                         'Segment register values are not propagated; memory operands are syntactic',
                         'Near tail branches can share bodies; candidate boundaries are not proven source functions'],
              'functions': sorted(functions.values(), key=lambda f: (f['module_offset'], f['entry']))}
    for name, data in [('direct-flow.json', result), ('memory-operands.json', memory), ('platform-sites.json', platform)]:
        (out/name).write_text(json.dumps(data, indent=2)+'\n', encoding='utf-8')
    (out/'instructions.txt').write_text('\n'.join(instructions)+'\n', encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k not in ('functions', 'overlap_module_offsets')}, indent=2))


if __name__ == '__main__':
    main()
