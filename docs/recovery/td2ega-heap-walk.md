# Raw segmented heap walk

`13A8:26F1` now has a C contract with actual280E and27D4 children, their
required ZF results, and full nested SS frames. It preserves the word request
guards, raw header-bit tests, merging/splitting, byte-only updates, segment
links, ES-based counter/export fields and ordered cursor stores.

CLD occurs once after the initial guards. Later LODSW instructions use the
actual DF returned through a child/service. The verified cases include
backward traversal after DF1 returns. DS changes follow actual segment
fields; ES remains a separate current view. Neither register is replaced
with a global principal-data assumption.

Success explicitly puts the offset in AX and current DS in DX. Its CF/ZF
come from comparing DS with SS, so a nonzero pointer can have ZF1. Failure
resets the cursor and uses XOR AX/word CWD to return AX/DX zero. Early guard
failure precedes CLD and retains incoming DF. The actual near-return word
is read after all metadata writes. The26A8 caller owns the outer frame;
its two known public callers discard arithmetic status with ADD SP,2.

The C17 `/W4 /WX` build passed10,960 comparisons,990,650 original
instructions and all237 feasible sites in the266-site family fence. The
29 child-parent exclusions retain the fixed2830 argument proof; standalone
2852 covers its complete body. Full bus/SS, GPR/BP/CF/IF/DF, required ZF,
requests, control and counts match. Coverage includes2,192 DF1 LODSW
executions,1,312 synthetic services,256 changed child returns and996 changed
root returns. Twenty-eight native diagnostics are separate. Earlier runs
matched but needed two focused alignment-failure cases and broader service
profiles. C/DLL remained unchanged.

RS276 records a22-byte initialized control candidate6F26..6F3B, containing
RS275's6F36 word. Current DS fields and explicit ES fields retain their
different views. Known parent/helper writes are recorded; all writers,
bindings, field units, capacities, ownership and lifetime remain open.

Whole26A8/public callers, historical CPU/A20 qualification, interrupt
exclusion and core integration remain open. Synthetic services omit real
DOS and INT frames. No DOS session, renderer, audio, complete state-machine,
gameplay or fidelity gate is established. CGA and later phases retain their
required order.
