"""Read-only admission of upstream address claims against the pinned EGA image.

This reconciles indexes and source locators, not function semantics. It neither
modifies accepted registries nor executes original or upstream code. Evidence
outputs are fresh and outside reference. Capstone is an already pinned tool.
"""
from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "analysis/tools/python"))
from capstone import Cs, CS_ARCH_X86, CS_MODE_16
from capstone.x86_const import X86_OP_MEM

UP = ROOT / "reference/repos/kylofon-test-drive-2-sdl3"
IMAGE = ROOT / "analysis/derived/td2ega-v1/TD2EGA.image.bin"
OUT = ROOT / "docs/recovery/evidence/kylofon-address-admission-v1.json"
DOC = ROOT / "docs/recovery/kylofon-address-admission.md"
EXPECTED = "8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4"
ADDRESS = re.compile(r"(?<![A-Za-z0-9_])([0-9a-fA-F]{4}):([0-9a-fA-F]{4})(?![0-9a-fA-F])")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def at(address):
    s, o = (int(v, 16) for v in address.split(":"))
    return s * 16 + o


def key(entry):
    return f'{entry["segment"]:04x}:{entry["segment_offset"]:04x}'


def pin(path):
    return {"path": path.relative_to(ROOT).as_posix(), "bytes": path.stat().st_size,
            "sha256": sha(path.read_bytes())}


def stripped(text):
    # Keep byte/string offsets and line numbers while ignoring comments/literals
    # for brace matching. Address claims are separately read from original text.
    pattern = r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
    return re.sub(pattern, lambda m: re.sub(r"[^\n]", " ", m.group()), text, flags=re.S)


def source_functions(path):
    text = path.read_text(encoding="utf-8")
    clean = stripped(text)
    depths, depth = [], 0
    for c in clean:
        depths.append(depth)
        if c == "{": depth += 1
        elif c == "}": depth -= 1
    pattern = re.compile(r"\b([A-Za-z_]\w*)\s*\(([^;{}]*)\)\s*\{", re.S)
    result, previous_end = [], 0
    for m in pattern.finditer(clean):
        brace = m.end() - 1
        if depths[brace] != 0:
            continue
        end = brace + 1
        while end < len(clean) and not (clean[end] == "}" and depths[end] == 1):
            end += 1
        if end == len(clean):
            raise ValueError("Unclosed source function: " + str(path))
        name = m.group(1)
        if name in ("if", "for", "while", "switch"):
            continue
        line_start = text.count("\n", 0, m.start(1)) + 1
        line_end = text.count("\n", 0, end) + 1
        # Prelude claims may describe a family, not only the following function.
        # Preserve the zone and never treat a body/callee marker as an entry proof.
        prelude = text[previous_end:m.start(1)]
        prelude_start = max(0, len(prelude) - 1600)
        start = previous_end + prelude_start
        tail_end = text.find("\n", end)
        if tail_end < 0: tail_end = len(text)
        claims = []
        for am in ADDRESS.finditer(text[start:tail_end]):
            position = start + am.start()
            claims.append({"address": f'{int(am.group(1),16):04x}:{int(am.group(2),16):04x}',
                           "line": text.count("\n", 0, position) + 1,
                           "zone": "prelude" if position < m.start(1) else "signature_or_body"})
        result.append({"name": name, "path": path.relative_to(ROOT).as_posix(),
                       "start_line": line_start, "end_line": line_end,
                       "source_sha256": sha(path.read_bytes()), "address_claims": claims})
        previous_end = tail_end
    return result


SPECIAL_UP = {
    "06c9:1a37": ("operand_byte_not_admitted_entry", "The byte at1A37 is the last segment byte of the five-byte far CALL beginning1A33. No selected direct-flow entry targets it. Upstream8F12's broad computed drawing traversal is not entry proof; retain only as a rejected index start pending any independent alternate-entry witness."),
    "06c9:607a": ("orphan_entry_with_shared_timer_tail", "Independent prologue607A computes1:0 IDIV[BP+6], publishes countdown metadata and enters6099 timer-install tail also reached by6059's JMP6077. The selected graph has no607A root. Preserve the candidate and no-callers qualification; no new stableFN assigned."),
    "06c9:7d9c": ("orphan_shared_blitter_prefix", "Distinct prologue/configuration prefix7D9C..7DBB JMP91C1 selects AND/clipped raw tables. Local7D7C/7DBC and other blitters share later bodies; absence of this root is not absent library code or accepted caller reachability."),
    "06c9:ac1c": ("orphan_shared_grab_prefix", "PrefixAC1C..AC3E subtracts member origin from supplied coordinates then JMPAC82, shared with admittedAC40. It is a separate uncalled entry candidate; AC40 evidence does not admit its different prefix."),
    "06c9:ac64": ("orphan_shared_grab_prefix", "PrefixAC64..AC81 reads stored member coordinates, masks x withFFF8 and falls intoAC82. Existing plane-gather context confirms13 prefix sites but leaves this entry open. Keep separate fromAC40's admitted76-site body."),
    "06c9:af54": ("data_misindexed_as_code", "CS:AF54 is a26-byte screen descriptor, passed to7D5E by accepted5C98; upstream symbols marks it global gfx_screen_desc. Linear disassembly of descriptor bytes must not create a callable root or infer a real CALL toC030."),
    "06c9:bae8": ("orphan_shared_blitter_prefix", "Distinct prologue/configuration prefixBAE8..BB07 JMP91C1 selects XOR/clipped raw tables. Adjacent admittedBAC8/BB08 prefixes and shared graphics paths do not establish a caller toBAE8."),
    "06c9:c030": ("interior_shared_graphics_instruction", "C030 is CMPBX,[BP-3C] inside the row loop reached linearly fromBFCF, with backward branchBFD2. Existing graphic ranges include it but no selected root/call does. Its upstream-only callerAF54 is data; reject new standalone entry inference."),
    "13a8:03ec": ("orphan_near_runtime_helper", "Twelve-byte near helper savesDS/ES, reads physical0012 throughDS0 and RETs. It lies after03D3's ordinary RET03EB; upstream's03D3 broad linear index lists it, but selected direct-flow has no caller. Keep code-candidate semantics and historical reachability separate."),
    "13a8:2da7": ("orphan_nonstandard_runtime_entry", "Prologue rewrites four stack words, adjustsBP and transfers through runtime dispatch path. It is not a normal epilogue-only function. No selected direct-flow caller or localFN exists; preserve candidate with exact stack effects pending full contract."),
}


SPECIAL_OUR = {
    "06c9:61bf": ("installed_interrupt_root_omitted_from_index", "Timer ISR has explicit upstream timer_isr C body while indexed function starts omit installed vector roots. OurFN360 keeps actual SS save/INT/IRET and alias/FLAGS evidence; upstream native body deliberately drops hardware frame details."),
    "06c9:6230": ("interrupt_chain_shared_tail_omitted_from_index", "LocalFN361 is saved-vector/BIOS-chain tail; upstream symbol timer_bios_chain exists but hardware chaining is replaced in host timer handling. Do not infer complete original body from the host timer ISR."),
    "06c9:6269": ("published_callback_root_omitted_from_index", "Effect callback sfx_tick is implemented explicitly in sound.c and invoked by native callback mapping; old index misses the callback root. Retain localFN403 and raw effect command/SS/port scopes."),
    "06c9:69b7": ("installed_interrupt_root_omitted_from_index", "Installed INT16 handler appears as kbd_int16_isr symbol and host keyboard behavior, not a standalone original ISR C implementation. LocalFN160 retains actual frames and AH branch coverage."),
    "06c9:8336": ("shared_graphics_entry_split", "Local mask/plane entry8336 is inside upstream82D0 range; upstream rect_set_plane implementation abstracts its screen/RAM paths. Exact instruction boundary is retained under localFN213."),
    "06c9:839c": ("shared_graphics_entry_split", "Local XOR plane entry839C has upstream rect_xor_plane symbol/implementation but is absent from index starts. Preserve localFN214 and raw alternate paths."),
    "06c9:ad8b": ("shared_graphics_entry_split", "LocalEGA plane-mask entryAD8B is represented by upstream rect_set_plane_ega family rather than a separately indexed root. KeepFN239's actual bus contract."),
    "06c9:adf4": ("shared_graphics_entry_split", "LocalEGA XOR-mask entryADF4 is represented by upstream rect_xor_plane_ega family rather than a separately indexed root. KeepFN240's actual bus contract."),
    "13a8:049b": ("installed_interrupt_root_inside_startup_index_span", "Local divide interrupt entry049B is within upstream03F8..04BE aggregate index range but begins a distinct installed handler with current CS near hook04BA. PreserveFN439 and all context/termination gaps."),
    "13a8:0644": ("shared_runtime_error_entry_inside_initializer_span", "Local0644 candidate falls within upstream0620 initializer range. Actual0644 MOVAX,2 then0647 JMP04AA enters the common runtime error report path, rather than an independent ordinary C function. PreserveFN359 and its pending contract; no source signature invented."),
}


def main():
    if OUT.exists() or DOC.exists():
        raise FileExistsError("Address-admission writer already consumed")
    image = IMAGE.read_bytes()
    if sha(image) != EXPECTED:
        raise ValueError("Wrong original image")
    functions_path = ROOT / "docs/recovery/functions.json"
    resources_path = ROOT / "docs/recovery/resources.json"
    flow_path = ROOT / "analysis/flow/indirect-v8/direct-flow.json"
    up_index_path = UP / "port/td2ega_functions.json"
    symbol_path = UP / "port/symbols.csv"
    ours = json.loads(functions_path.read_bytes())["records"]
    resources = json.loads(resources_path.read_bytes())["records"]
    flows = json.loads(flow_path.read_bytes())["functions"]
    ups = json.loads(up_index_path.read_bytes())["functions"]
    symbols = list(csv.DictReader(symbol_path.read_text(encoding="utf-8").splitlines()))
    own_by = {key(f["entries"][0]): f for f in ours}
    up_by = {f["start"].lower(): f for f in ups}
    symbol_by = defaultdict(list)
    for line, row in enumerate(symbols, 2):
        row = dict(row, line=line)
        symbol_by[row["address"].lower()].append(row)
    decoder = Cs(CS_ARCH_X86, CS_MODE_16)
    decoder.detail = True
    source = []
    for p in sorted((UP / "td2port/src").rglob("*.c")):
        source.extend(source_functions(p))
    source_by_name = defaultdict(list)
    for f in source:
        source_by_name[f["name"]].append(f)
    source_mentions = defaultdict(list)
    names = {s["name"] for s in symbols if s["kind"] == "func"}
    for p in sorted((UP / "td2port/src").rglob("*")):
        if p.suffix not in (".c", ".h"): continue
        for line, text in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            for token in set(re.findall(r"\b[A-Za-z_]\w*\b", text)) & names:
                source_mentions[token].append({"path":p.relative_to(ROOT).as_posix(),"line":line,
                                               "scope":"token mention/declaration/macro locator, not independent implementation proof"})
    instruction_owners, syntactic_memory = defaultdict(set), defaultdict(list)
    for f in flows:
        seg = int(f["entry"].split(":")[0], 16)
        for off in f["instructions"]:
            offset = seg * 16 + off
            instruction_owners[offset].add(f["entry"])
            ins = next(decoder.disasm(image[offset:offset + 15], off, count=1), None)
            if ins is None: continue
            for operand in ins.operands:
                if operand.type != X86_OP_MEM: continue
                m = operand.mem
                displacement = m.disp & 0xffff
                segment = ins.reg_name(m.segment) if m.segment else ("ss" if ins.reg_name(m.base) in ("bp", "sp") else "ds")
                if segment == "ds":
                    record = {"site": f'{seg:04x}:{off:04x}', "mnemonic": ins.mnemonic,
                              "bytes_read_or_written": operand.size, "base": ins.reg_name(m.base),
                              "index": ins.reg_name(m.index), "displacement": f'{displacement:04x}',
                              "segment_assumption": "currentDS only; no global178F binding inferred"}
                    syntactic_memory[displacement].append(record)
    def definitions(address):
        found = []
        for s in symbol_by[address]:
            if s["kind"] != "func": continue
            names = [s["name"]] + s["other_names"].split(";")
            for name in names:
                for definition in source_by_name.get(name.strip(), []):
                    found.append({k: definition[k] for k in ("name", "path", "start_line", "end_line", "source_sha256")})
        return list({(x["path"], x["name"]): x for x in found}.values())
    def instruction_sample(address, count=12):
        s, o = (int(v, 16) for v in address.split(":"))
        return [{"address": f'{s:04x}:{i.address:04x}', "size": i.size,
                 "mnemonic": i.mnemonic, "operands": i.op_str}
                for i in list(decoder.disasm(image[at(address):at(address)+64], o))[:count]]
    def containing_ranges(offset):
        return [{"id": f["id"], "range_offset": z["offset"], "range_length": z["length"]}
                for f in ours for z in f["ranges"] if z["offset"] <= offset < z["offset"] + z["length"]]
    upstream_only = []
    for address in sorted(set(up_by) - set(own_by)):
        u = up_by[address]
        classification, disposition = SPECIAL_UP.get(address, ("orphan_library_code_candidate", "A real instruction prologue/body and upstream semantic symbol exist, but the selected graph has no direct caller/root for this entry. Preserve as a separately named candidate; no newFN contract or supported-path reachability accepted."))
        upstream_only.append({"address": address, "module_offset": at(address), "classification": classification,
                              "disposition": disposition, "upstream_index": u,
                              "upstream_symbols": symbol_by[address], "source_definitions": definitions(address),
                              "our_instruction_owners": sorted(instruction_owners[at(address)]),
                              "our_containing_ranges": containing_ranges(at(address)),
                              "original_instruction_sample": instruction_sample(address),
                              "semantic_admission": "not promoted; existing owners/indirect/lifetime obligations retained"})
    ours_only = []
    for address in sorted(set(own_by) - set(up_by)):
        o = own_by[address]
        classification, disposition = SPECIAL_OUR.get(address, ("indirect_object_entry_omitted_from_index", "A near object-dispatch target4929..4A19 has explicit upstream C implementation/symbol despite absence from its function index. Retain our stableFN, actual near-call contract, SS/FLAGS/alias scopes and unresolved valid target domains."))
        ours_only.append({"address": address, "our_id": o["id"], "classification": classification,
                          "disposition": disposition, "our_code_contract_status": o["gates"]["code_contract"]["status"],
                          "upstream_symbols": symbol_by[address], "source_definitions": definitions(address),
                          "upstream_containing_index_spans": [z["start"] for z in ups if at(z["start"])<=at(address)<at(z["end"])],
                          "original_instruction_sample": instruction_sample(address),
                          "retained_local_sources": [z["path"] for z in o["portable_source"]]})
    conflicts = []
    for row in symbols:
        if not row["other_names"]: continue
        address = row["address"].lower()
        candidates = []
        for s in symbol_by[address]:
            if s["kind"] == row["kind"]: candidates.append(s)
        line = candidates[0]["line"]
        if row["kind"] == "func":
            local = own_by.get(address)
            stable = local["id"] if local else "CANDIDATE-FUNC-" + address.replace(":", "-").upper()
            role = "existing original entry identity; semantic labels remain aliases"
            refs = []
            status = local["gates"]["code_contract"]["status"] if local else "pending"
        else:
            off = int(address.split(":")[1], 16)
            stable = "CURRENT-DS-VIEW-" + f'{off:04X}' if address.startswith("ds:") else "RAW-VIEW-" + address.replace(":", "-").upper()
            role = "currentDS raw field/table view; fixed segment and gameplay units not inherited"
            refs = list({(q["site"],q["mnemonic"],q["base"],q["index"]):q for q in syntactic_memory[off]}.values())
            status = "syntactic_xrefs_only" if refs else "address_alias_only"
        # Preserve every naming choice, do not let a merge policy turn one into
        # claimed original semantics. 'Chosen' is a neutral stable identity.
        aliases = [row["name"]] + [v.strip() for v in row["other_names"].split(";") if v.strip()]
        locs = []
        if row["kind"] == "global" and address.startswith("ds:"):
            off = int(address[3:],16)
            for res in resources:
                for loc in res.get("locations",[]):
                    if loc.get("segment")==0x178f and loc["segment_offset"]<=off<loc["segment_offset"]+loc["length"]:
                        locs.append(res["id"])
        conflicts.append({"kind":row["kind"],"address":address,"symbol_csv_line":line,
                          "chosen_identity":stable,"role":role,"aliases_preserved":aliases,
                          "upstream_preferred_name":row["name"],"owner":row["owner"],"type_candidate":row["type"],
                          "status":status,"original_xrefs":refs,"existing_resource_views":sorted(set(locs)),
                          "source_definitions":definitions(address) if row["kind"]=="func" else [],
                          "resolution":"Naming disagreement resolved by address identity and retaining every alias; no global semantic rename or contract promotion. Existing local semantic evidence remains authoritative."})
    crosswalk = []
    for s in symbols:
        if s["kind"]!="func": continue
        address=s["address"].lower()
        if not re.fullmatch(r"[0-9a-f]{4}:[0-9a-f]{4}",address):
            raise ValueError("Unexpected function address: "+address)
        offset=at(address)
        if not 0<=offset<len(image): raise ValueError("Function symbol outside admitted image")
        local=own_by.get(address)
        up=up_by.get(address)
        span= {"start":up["start"],"end":up["end"],"bytes":up["size"],
               "sha256":sha(image[offset:offset+up["size"]]),
               "scope":"upstream heuristic span, not admitted complete function range"} if up else None
        crosswalk.append({"address":address,"module_offset":offset,"upstream_name":s["name"],
                          "stable_local_id":local["id"] if local else None,
                          "original_entry_gate":local["gates"]["code_contract"]["status"] if local else "pending_candidate",
                          "upstream_index_span":span,"source_definitions":definitions(address),
                          "source_symbol_mentions":source_mentions[s["name"]],
                          "source_comment_locators":[{"name":f["name"],"path":f["path"],"function_start_line":f["start_line"],"claim_line":c["line"],"claim_zone":c["zone"]} for f in source for c in f["address_claims"] if c["address"]==address],
                          "our_containing_ranges":containing_ranges(offset),
                          "our_instruction_owners":sorted(instruction_owners[offset]),
                          "claim_scope":"source/address crosswalk only; range hashes do not prove code/data or source semantic parity"})
    all_addresses=sorted(set(own_by)|set(up_by)|{s["address"].lower() for s in symbols if s["kind"]=="func"})
    all_crosswalk=[]
    for address in all_addresses:
        offset=at(address)
        if not 0<=offset<len(image): raise ValueError("Candidate address outside original image")
        local=own_by.get(address)
        up=up_by.get(address)
        all_crosswalk.append({"address":address,"module_offset":offset,
                              "stable_local_id":local["id"] if local else None,
                              "is_upstream_index_start":bool(up),
                              "upstream_function_names":[s["name"] for s in symbol_by[address] if s["kind"]=="func"],
                              "upstream_global_names":[s["name"] for s in symbol_by[address] if s["kind"]=="global"],
                              "source_definitions":definitions(address),
                              "source_comment_locators":[{"name":f["name"],"path":f["path"],"function_start_line":f["start_line"],"claim_line":c["line"],"claim_zone":c["zone"]} for f in source for c in f["address_claims"] if c["address"]==address],
                              "our_original_ranges":[{"offset":z["offset"],"length":z["length"],"sha256":sha(image[z["offset"]:z["offset"]+z["length"]])} for z in local["ranges"]] if local else [],
                              "our_code_contract_gate":local["gates"]["code_contract"]["status"] if local else "pending_candidate",
                              "upstream_index_span": {"start":up["start"],"end":up["end"],"bytes":up["size"],"sha256":sha(image[offset:offset+up["size"]]),"scope":"heuristic span only"} if up else None,
                              "our_instruction_owners":sorted(instruction_owners[offset]),
                              "scope":"Complete union of440 localentries,444 indexstarts and460 upstream function symbols; candidate navigation/range identity only."})
    # Boundary tests use authoritative decoded selected sites, with exact byte
    # sizes, rather than assuming every address in a min/max range is executable.
    boundaries=[]
    offsets = sorted(instruction_owners)
    for a in set(up_by) | set(own_by):
        pos=at(a)
        for off in range(max(0,pos-14),pos):
            if off not in instruction_owners: continue
            i=next(decoder.disasm(image[off:off+15],0,count=1),None)
            if i and off<pos<off+i.size:
                boundaries.append({"candidate":a,"inside_selected_instruction_offset":off,
                                   "instruction_size":i.size,"selected_owners":sorted(instruction_owners[off]),
                                   "qualification":"Cross-segment/alternative-state overlap requires review; not globally rejected just by this check."})
    assert_counts=(len(upstream_only),len(ours_only),len(conflicts),len(crosswalk))
    if assert_counts!=(27,23,76,460): raise ValueError("Unexpected reconciliation counts: "+str(assert_counts))
    report={"schema":1,"date":"2026-10-22","result":"pass_bounded_address_reconciliation",
            "scope":"Static original-byte/index/source admission only. Orphan entry reachability, original semantics and runtime/fidelity remain separately open; no registries changed.",
            "upstream_commit":"352b56824d8c91e938b8f0794a71afca9a276193",
            "inputs":[pin(p) for p in [IMAGE,functions_path,resources_path,flow_path,up_index_path,symbol_path]],
            "maker":pin(Path(__file__).resolve()),
            "provisional_attempts":[{"archive":"analysis/reviews/kylofon-address-admission-draft-v1","issue":"First unpublished draft treated saved direct-flow instruction offsets as module offsets; corrected to segment*16+offset before admission. That draft is not valid evidence.0644 manual disposition was also corrected to literalMOVAX2/JMP04AA.","accepted":False},{"archive":"analysis/reviews/kylofon-address-admission-draft-v2","issue":"Corrected draft retained before adding complete495-address union and source macro/token locators; no semantic acceptance existed.","accepted":False}],
            "summary":{"our_entries":len(own_by),"upstream_index_starts":len(up_by),
                       "exact_start_matches":len(set(own_by)&set(up_by)),"upstream_only_reconciled":len(upstream_only),
                       "local_only_reconciled":len(ours_only),"symbol_conflicts_reconciled":len(conflicts),
                       "function_symbols_crosswalked":len(crosswalk),"c_function_definitions_parsed":len(source),
                       "source_definitions_bound_by_function_name":sum(bool(x["source_definitions"]) for x in crosswalk),
                       "complete_candidate_address_union":len(all_crosswalk),
                       "entry_index_union":len(set(own_by)|set(up_by)),
                       "selected_instruction_boundary_overlap_claims":len(boundaries)},
            "method_limits":["All addresses are unrelocated module-segment:offset; runtime load relocations are separate.",
                             "Source function-name binding is a locator, not a guessed ABI or source-to-instruction proof.",
                             "Comment body/prelude claims may reference callees/families; zones are retained and not treated as entry guarantees.",
                             "Original xrefs are syntactic currentDS displacement references from the selected graph, not complete indirect/all-writer/lifetime closure.",
                             "Existing registry ranges can be shared/gapped and are not treated as linear executed ranges.",
                             "Capstone's16-bit98/99 mnemonic aliases require CBW/CWD interpretation; no arithmetic semantics derived from its spelling here."],
            "upstream_only":upstream_only,"local_only":ours_only,"symbol_conflicts":conflicts,
            "function_source_crosswalk":crosswalk,"complete_candidate_address_crosswalk":all_crosswalk,"source_function_comment_claims":source,
            "selected_instruction_boundary_overlap_claims":boundaries,
            "open_admission_limits":["Uncalled/orphan code candidates need independent historical caller/reachability or documented disposition before wholeEGA closure.",
                                     "All unsupported original ISR/stack/DS/SS/hardware paths remain explicit native-adaptation gaps.",
                                     "Shared graphics tails require state-specific mutable-code/domain evidence; a source index cannot replace it.",
                                     "Unknown gameplay names/units remain aliases, not newly accepted semantics."]}
    OUT.write_bytes((json.dumps(report,indent=2)+"\n").encode())
    lines=["# Kylofon address and symbol admission", "", "Date:22 October2026. Pinned upstream commit `352b56824d8c91e938b8f0794a71afca9a276193`. This is bounded static reconciliation against the independently validated EGA image, not source-semantic or gameplay acceptance.", "",
           "[Machine evidence](evidence/kylofon-address-admission-v1.json) contains input/maker hashes, all 50 unmatched-start dispositions, all 76 naming conflicts with original syntactic xrefs, all 460 function-symbol/source mappings, the complete 495-address union of local entries/upstream index starts/function symbols, complete C-definition comment claims and boundary/range qualifications. No original, clone file, accepted source, registry or old receipt was changed.", "",
           "## Results", "", f"417 exact starts;27 upstream-only and23 local-only starts individually reconciled. All76 naming conflicts are keyed to stable localFN or neutral currentDS raw-view identities, with every upstream alias retained. {len(source)} C definitions were parsed; {sum(bool(x['source_definitions']) for x in crosswalk)} of460 function symbols bind by name to actual C definitions. Names and span hashes do not prove semantics.", "",
           "The two most consequential upstream-index errors are06C9:AF54, which is a screen descriptor rather than an admitted code root, and06C9:1A37, an operand byte inside CALL1A33. The purported AF54→C030 call is not source of reachability proof: C030 is an interior shared graphics instruction. Real x86 alternate entries are possible, so rejection is scoped to these unmutated index claims; any independent alternate-entry witness would require new analysis.", "",
           "Most other upstream-only starts are coherent uncalled library entries with distinct prologues, sometimes sharing tails with known routines. They are retained as candidates without assigning new accepted functionIDs. Their existence is useful discovery and does not establish a supported caller or complete contract. All13 local-only object callbacks4929..4A19 have explicit upstream C/symbol counterparts. Interrupt/callback roots and shared graphics entry splits explain the other local index omissions; the installed-handler raw contracts remain ours.", "",
           "## All unmatched starts", "", "| Direction | Address | Stable local identity | Disposition |", "| --- | --- | --- | --- |"]
    for row in upstream_only: lines.append(f"| Upstream only | `{row['address'].upper()}` | retained candidate | {row['classification']}: {row['disposition']} |")
    for row in ours_only: lines.append(f"| Local only | `{row['address'].upper()}` | `{row['our_id']}` | {row['classification']}: {row['disposition']} |")
    lines += ["", "## All naming conflicts", "", "The chosen identifier is deliberately neutral where original gameplay semantics or DS binding are unproved. Per-row xrefs and resource-span associations are in JSON. Resolve navigation names without rewriting existing accepted contracts or claiming global ownership/lifetime proof.", "", "| Original address | Chosen identity | Upstream aliases retained | Role/evidence status |", "| --- | --- | --- | --- |"]
    for row in conflicts: lines.append(f"| `{row['address'].upper()}` | `{row['chosen_identity']}` | {', '.join('`'+x+'`' for x in row['aliases_preserved'])} | {row['status']} |")
    lines += ["", "## Source and range admission rules", "", "Each original function symbol is linked to an actual C definition when its preferred name or retained alias matches. The JSON pins source files, line ranges, original upstream index span hash and existing local entry/range owners. Every C function's address comments are also retained with their line and prelude/body zone. A comment mentioning a callee does not make the surrounding function that callee. Source-name/comment mapping remains a candidate locator for the representative differential tests.", "",
              "Original module offsets are segment*16+offset. No load-segment relocation is silently applied. Existing local ranges are shared and sometimes gapped; membership alone is not a complete execution proof. The selected direct-flow graph has no intra-state overlapping instruction bytes, but upstream indexed spans may include data, other entries or unreachable linear fallthrough. Marker/range differences therefore do not cause bulk function-status changes.", "",
              "All naming conflicts now have an explicit address-based disposition. That closes the ambiguity of which bytes/view a label denotes, while semantic aliases/units and valid historical caller domains stay unpromoted until their own evidence exists. Upstream globalDS annotations are excluded; original xrefs are recorded only as currentDS syntactic displacements. No imported source may inherit our earlier bus/FLAGS/SS differential passes without an explicit checked adapter.", "",
              "## Remaining gates", "", "P1-R02 address/navigation reconciliation is complete at this bounded scope. Independent candidate input/unpacker identity, per-site deviation/embedded-data classification and the memory/caller profile are owned by the accompanying admission work. P1-R03 still needs its representative candidate build/comparisons. The uncalled library entries, installed handler adaptations, shared/mutable graphics domains, all writers/lifetimes and entire reachableEGA semantics remain obligations forP1-05..11. NoCGA/resource/gameplay/visual/audio/fidelity acceptance is established here."]
    DOC.write_bytes(("\n".join(lines)+"\n").encode())
    print(json.dumps(report["summary"],indent=2))


if __name__ == "__main__":
    main()
