# TD2EGA startup, data group and main candidate

Date: 2026-10-13. Phase 1, bounded **static analysis only**. Input is the independently verified raw load image under `analysis/derived/td2ega-v1/TD2EGA.image.bin`, SHA-256 `8db38a02cc318a62b15928e217bb9f935699c6566088c21d32382a1c908a59c4`. Original packed source SHA-256 is `eb4f8e882fd79e884260b2285f38cc22673d45ddc5f601a5815bcce42d5a7182`.

No application instruction, BIOS/DOS service, hardware access, game loop, or renderer was executed for this analysis. Private byte-bearing listings and direct-flow notes are under `analysis/startup`; sanitized coordinates, hashes and conclusions are in [td2ega-startup.json](evidence/td2ega-startup.json). This report does not establish playable gameplay, complete code coverage, resource schemas, physics, or original presentation fidelity.

## Coordinate rules

All segmented addresses below are **load-relative original segments**. A module byte offset is `segment * 16 + offset`. A runtime/tool import with load segment `L` adds `L` to a relocatable segment word; it does not add `L` to the offset. The packed file's offsets are a separate coordinate system.

For example, original `13A8:03F8` maps to module `0x13E78` and to synthetic runtime/tool `23A8:03F8` when `L=0x1000`. Original `0000:07B3` maps to module `0x07B3` and tool `1000:07B3`; it is not a call into real-mode segment zero.

## Principal findings

- `FN-EGA-000001`: original `13A8:03F8` is compiler/C-runtime startup, not the game main loop.
- The principal near-data and normal C stack group is load-relative segment **`0x178F`**. It is established through DI and SS, then copied into DS; a loader heuristic that only recognizes a direct DS-immediate sequence can miss it.
- Startup calls `0000:07B3` after constructing and pushing three words consistent with `argc`, near `argv`, and near `envp`. This is the strong application `main` candidate, reserved as `FN-EGA-000002`.
- The main candidate contains a verified static comparison against the executable-resident `herc` option, branches to distinct graphics initialization paths, references the original sound/title filenames, and has a bounded direct-flow body ending at `0000:0C03` with a far return.
- Root-selected `FN-EGA-000003`, `06C9:[780E,782B)`, is independently confirmed as a small deterministic state transformation. Its gameplay purpose remains unknown.

## 1. Startup and runtime scaffolding

The entry region `13A8:[03F8,04BE)` is 198 bytes, SHA-256 `4b5d3d07ec111f996677a97ac52c368282f8e2199150988dc02fc3285f85056c`. Its initial portion queries DOS version and exits on a pre-2.x result. That identifies an operating-system/runtime setup boundary rather than game simulation.

| Original location | Verified operation | Interpretation and limit |
|---|---|---|
| `13A8:03F8`–`0400` | DOS `INT 21h` with `AH=30h`, compare returned AL to 2, older-version `INT 20h` path | DOS/runtime startup |
| `13A8:0402` | Load DI with relocated segment `178Fh` | Principal data/stack group candidate; relocation proven below |
| `13A8:0405`–`0411` | Read PSP word 2, subtract DI, cap paragraph difference at `1000h` | Establish available near-group span capped at 64 KiB |
| `13A8:0414`–`041B` | Interrupt exclusion around `SS=DI`, `SP += 942Eh` | Move C stack into principal data group |
| `13A8:041C`–`0430` | Carry-dependent error path, runtime calls and DOS termination | Error path, not normal game initialization |
| `13A8:0432`–`0447` | Align SP and save stack/limit values at SS offsets `6D2A`, `6D26`, `6D24` | Runtime stack/allocation bookkeeping; exact field names remain provisional |
| `13A8:044B`–`0459` | Update PSP memory-end word and call DOS resize service `AH=4Ah` | Runtime allocation adjustment |
| `13A8:045B` | Save incoming DS to SS:`6D9B` | Save PSP segment for later argument/environment access |
| `13A8:0460`–`046D` | ES becomes SS; clear bytes `[83C8h,9430h)` with AL=0 | Static-data/BSS initialization |
| `13A8:046F`–`0470` | DS becomes SS | Establish ordinary near-data accesses relative to `178Fh` |
| `13A8:0471` | Far call `13A8:04BE` | Runtime initialization; DOS version, divide-vector and file-handle/environment setup are visible in its bounded body |
| `13A8:0476`–`0477` | DS becomes SS again | Reassert data group after runtime initialization |
| `13A8:0478` | Far call `13A8:0826` | Build near-pointer environment array; resulting pointer stored at DS:`6DBC` |
| `13A8:047D` | Far call `13A8:0694` | Parse PSP command line, build argc/near argv, then far-transfer back through saved return address |
| `13A8:0482` | Clear BP | Startup frame boundary |
| `13A8:0484`, `0488`, `048C` | Push words at DS:`6DBC`, `6DBA`, `6DB8`, respectively | Environment pointer, argument-vector pointer, argument count |
| `13A8:0490` | Far call `0000:07B3` | Application main candidate |
| `13A8:0495`–`0496` | Push returned AX; call `13A8:0582` | Runtime exit/cleanup candidate consuming main's return value |

The argument routine at `13A8:0694` reads the PSP command-tail area starting at `81h`, distinguishes whitespace, quotes and backslashes, stores count at DS:`6DB8`, allocates the near argv vector on the C stack and stores its pointer at DS:`6DBA`. Its final indirect far jump at `13A8:0822` resumes the saved caller return. This unusual return mechanism must not be mistaken for an unresolved game dispatch table.

The environment routine `13A8:[0826,088C)` scans PSP environment metadata, copies strings and constructs a near pointer array stored through DS:`6DBC`. The three-word call contract is strong evidence for a C-style `main(argc, argv, envp)` interface using near data pointers. Far code plus these near runtime data pointers is consistent with a medium-style memory model, but no exact compiler option or original source signature is claimed.

## 2. Data/stack group and relocation proof

The immediate word in `MOV DI,178Fh` is at module offset **`0x13E83`**, and is an admitted relocation site. The main-call segment word at module **`0x13F13`** is another admitted relocation site, initially zero in the raw image. Therefore:

| Quantity | Load-relative | Synthetic load `L=1000h` |
|---|---:|---:|
| Initial application code segment | `13A8` | `23A8` |
| Principal DS/normal SS group | `178F` | `278F` |
| Main-candidate code segment | `0000` | `1000` |
| Initial packed-metadata application stack | `20D2:0FA0` | `30D2:0FA0` |
| Rebased/aligned startup stack before runtime callees | `178F:A3CE` | `278F:A3CE` |

The last row is a **static calculation**, `0FA0h + 942Eh = A3CEh`, under the checked loader stack metadata. It has not been observed by running C startup. The new stack's physical/module location is two bytes below the initial metadata stack top, as the adjustment deliberately uses `942Eh` while the SS-group delta is `9430h` bytes.

The zeroing range `[DS:83C8, DS:9430)` is 4,200 bytes, module `[0x1FCB8,0x20D20)`. The first eight bytes overlap the end of the 130,240-byte initialized image; the remaining span extends into allocation-backed zero-initialized data. Its upper bound equals the original metadata SS base. Do not truncate the memory model to the file-backed image or treat this span as an out-of-bounds corruption solely because it extends beyond EOF.

DS is not constant across every instruction. It initially points to the PSP, becomes the principal group on the normal path at `0470`, temporarily becomes CS/PSP/environment inside runtime helpers, and is restored afterward. A Ghidra context correction should be range-specific. Setting DS globally to `278Fh` would misinterpret the early PSP accesses.

No Ghidra loader address error is established by this Capstone-only review. The concrete import checks are entry `23A8:03F8`, main call `1000:07B3`, relocated DI word `278Fh`, and appropriate DS/SS context after setup. Missing DS context is an analysis limitation; a wrong far-call target or missing relocation would be an actual import error.

## 3. Main candidate and initial application call chain

The main-candidate span `0000:[07B3,0C04)` is 1,105 bytes, SHA-256 `4fc9806151701d45debe3cc22159765d9bd7f32b8a31b5f44b80548f054c2dee`. A bounded traversal following direct branches and fallthrough, while recording but not entering callees, finds 360 instruction locations, 56 direct call sites (48 far, 8 near), no indirect branch in this body, and one far-return location at `0C03`.

Those are syntactic direct-flow observations, not exercised-path coverage. The referenced callees and their indirect behavior are not included in that count. All eight near-call encodings are immediately preceded by `PUSH CS`, supplying a far-return frame; their encoding alone does not establish near-return callees.

| Caller | Callee | Bounded observation |
|---|---|---|
| `0000:07C8` | `06C9:6F86` | Push `A000h` and call onward to `06C9:6F1E`; memory/display-manager role requires further tracing |
| `0000:07CD` | `06C9:5D83` | External-memory word read; exact address anomaly below |
| `0000:07DF` | `13A8:2988` | Near-string comparison routine, verified by null scan and byte comparison; inputs include argv entry and DS:`7187` (`herc`) |
| `0000:07EB` | `06C9:5F64` | Equality branch: video BIOS call plus ports `3BFh`, `3B8h`, `3B4h`, memory `B800h`; Hercules initialization candidate |
| `0000:07F7` | `06C9:90E8` | Other branch: EGA ports `3CEh/3CFh`, BIOS mode `0Dh`, palette call; EGA initialization candidate |
| `0000:0804` | `06C9:6A17` | Register callback far pointer in DS:`64DC/64DE`; not a pure routine |
| `0000:080C` | `16FC:0002` | Unclassified initialization; no purpose assigned |
| `0000:0811` | `06C9:6860` | PIC masking and installation of vector entries at physical `24h/26h` and `58h/5Ah`, then restore mask; input/runtime service setup candidate |
| `0000:083B`, `084E` | `06C9:6D18` | Pass DS strings `voices.bin` and `songs.bin`; receive AX:DX and store far-pointer-shaped pairs |
| `0000:0865`, `0879` | `06C9:75C8`, `06C9:758A` | Consume those returned pairs; audio semantics not yet assigned |
| `0000:088D` | `06C9:B0FE` | Pass literal dimensions `140h`, `C8h` and value `0Fh`; store returned pair at DS:`8CA2/8CA4`; object/graphics allocation candidate |
| `0000:08B0`, `0934`, `09A5` | `0000:05C0` | Application-local calls; selectors/status values require tracing |
| `0000:0A98`, `0A9C` | `0000:0651`, `0000:0730` | Local application setup calls before larger orchestration |
| `0000:0A9F` | `0645:0000` | Application routine whose returned AX controls exit branch; purpose unknown |
| `0000:0AB9` | `00C0:039C` | Repeated application call; returned AX compared with escape (`1Bh`) and later `y/Y`; not yet classified as menus or racing |
| `0000:0BBB` | `019E:06C5` | Return controls repeat to `0AB9` or cleanup; purpose unknown |
| `0000:0BE4` onward | `06C9:610A`, `68C4`, `5FBC` or `642E` | Cleanup/graphics restoration candidates before far return |

The executable-resident `herc`, `voices.bin`, `songs.bin` and `testdrv2.pes` literals are at DS offsets `7187`, `718C`, `7197` and `71A3`. Their original resource consumers are future recovery targets; recognizing a name does not decode its data or prove its runtime use in every path.

### Address anomaly to preserve

`06C9:5D83` literally sets ES to `0040h` and reads word ES:`046Ch`, corresponding to physical `0x086C`. Companion `06C9:5D8D` reads the same address and subtracts a stack argument. Do not silently rewrite the offset to `006Ch` or call this a validated BIOS-tick implementation. The observed address could reflect an original defect or build-specific behavior; this review has no runtime observation or original-edition differential evidence to resolve it.

## 4. Independent next-leaf review: FN-EGA-000003

Root selected original **`06C9:[780E,782B)`**, module `[0x0E49E,0x0E4BB)`, for the first small C state transformation. Its 29 bytes hash to `f138992baf1f9cf7843fd61b1cc51d4f9bd3e5f2fe158e98a15bfca435367f66`.

Independent instruction review confirms this contract:

1. Decrement the 16-bit word at DS:`66E6` with modulo-65,536 wrap.
2. Select index `new_cursor & 0xFF` into the 256-byte region beginning DS:`66E8`.
3. Read the selected old byte and compute `((old_byte << 1) | (old_byte < 128)) & 0xFF`.
4. Store the computed byte back at that index and return it zero-extended in AX.
5. Restore SI. No call, interrupt, port I/O or other external access occurs. Explicit data writes are the cursor word and the selected byte only.

The comparison against `80h` supplies carry to the rotate-through-carry; using the incoming carry flag or an ordinary left rotate would be incorrect. The final `XOR AH,AH` sets CF=OF=0, ZF=PF=1 and SF=0; AF is undefined. A machine-register fixture should account for those flag effects rather than assuming all flags are preserved.

This is a deterministic state transformation suitable for isolated instruction-to-C differential testing. It is not a stateless mathematical function, and **no RNG, encryption, audio, gameplay, or rendering purpose is assigned**. AX is an observed postcondition exposed by the recovered interface; a decompiler's `void` return hypothesis cannot be accepted or refuted without caller-use evidence, since void functions may clobber AX. This report does not implement its C translation or run its tests; root owns that bounded recovery.

## 5. Tool and remaining limits

Private listings used the locked Capstone distribution version `5.0.9`; its Python `__version__` reports `5.0.7`. A two-byte synthetic disassembly check confirms that this build prints single-byte `98h`/`99h` as `cwde`/`cdq` even in 16-bit mode. For these unprefixed instructions the 16-bit interpretations are **CBW/CWD**. Preserve operand width from instruction bytes and mode; do not use the printed alias to introduce 32-bit arithmetic into the reconstruction. This naming discrepancy is a tool-output issue, not evidence of a game or MZ-loader defect.

The Microsoft runtime notice and startup pattern support a runtime boundary, but exact compiler version/options remain unknown. Routine names beyond those with direct instruction/data evidence remain candidates. The report establishes startup and address conventions for subsequent recovery, not a full state model or a playable game.
