# Report parent and keyboard cleanup with actual SS

18 October 2026. [C17 interface](../../src/recovered/td2ega_runtime_report_bus.h),
[build](evidence/td2ega-runtime-report-bus-build-v1.json),
[4,906 comparisons](evidence/td2ega-runtime-report-bus-validation-v1.json),
[context review](evidence/td2ega-runtime-report-bus-context-v1.json),
[51 native diagnostics](evidence/td2ega-runtime-report-bus-native-diagnostics-v1.json)
and [432 low-memory alias comparisons](evidence/td2ega-runtime-report-bus-alias-validation-v1.json)
admit a report-parent profile at16A7:0002 and an additional full SS view of
06C9:68C4. Older typed keyboard and accepted child sources remain frozen.

The primary corpus executes4,404,970 original instructions: all13 admitted
parent sites of15 and all22 cleanup sites,269 of342 total union sites. Actual
642E/840A,68C4,610A,29F6 and its message/exit children execute. Formatter0B00
remains a typed retired ABI profile with an explicit source-body gap.358
synthetic callback RETF operations are counted separately. Child-unit coverage
remains separate from this caller corpus.

Five arguments are read through the current returned BP, one SS word immediately
before each PUSH. A BIOS profile changes BP so each PUSH replaces its next
source word:312 witnesses forward five5678 words. Caching BP or all inputs
would lose that behavior. Actual retired CS/IP/SP is checked before continuation.
The formatter leaves ten argument bytes; ADDSP0A removes them and defines
arithmetic flags before29F6.

Cleanup saves the PIC byte in AH, masks with OR3, then conditionally restores
four IVT words and clears BDA0417's low nibble. It restores PIC from actual AH.
Only saved offset DS62AE guards the writes. No CLI/STI or stronger pointer guard
is inserted.432 additional comparisons expose192 changed far-return word pairs
when low-memory SS frames overlap these writes. Root return operations are
reported and never followed. RS305 records the external eight-byte saved-vector
view and installer writer sites; all writers, bindings and lifetimes remain open.

The primary corpus has4,196 retired cleanup roots,196 prepared DOS exits,148
raw child returns,350 budget prefixes and16 qualified preRET prefixes. Full1MiB
RAM, GPR/BP/CF/IF/DF/definedFLAGS, ordered BIOS/device/port/DOS requests and CPU
write counts match. Partial flags stay masked. Flat video RAM is not an actual
EGA device or renderer.

INT21/AH4C is prepared, not executed. The two parent epilogue sites after29F6
are not followed under this qualified profile. Full0B00/192C/stream dependencies
and DS/SS near-argument correspondence remain required before B264's descriptor
arena fallthrough can be qualified. No B0FE graph pruning. Actual callers,
all writers, storage/IRQ lifetimes, complete state-machine/core and P1-GATE
remain open. Physical086C stays unassigned; CGA stays behind EGA closure.
No DOS game session, renderer/audio output, gameplay or fidelity acceptance.
Full resources, Windows gameplay and Amiga recovery have not started.
