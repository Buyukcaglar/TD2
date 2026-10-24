# Sprite AND, OR and XOR code contracts

The [selected comparison](evidence/td2ega-sprite-logic-validation-v4.json)
passed23,568 synthetic vectors,11,089,922 original instructions, all1,988
owned instruction locations and all306 locations of the six near mask helpers.
There are19,786 ordinary far returns,3,686 native work prefixes and96 raw
unsupported dispatch transfers. These are distinct outcomes. Six native
invalid-interface checks are recorded separately.

7DBC, A718 and BB08 each take two SS words, source offset and segment.
Their coordinates come from source header+8/+A. They retain saved BP/DS/SI/DI,
materialized SS locals and pointer vectors, actual near mask-call frames and
plain far return with caller cleanup. The [static review](evidence/td2ega-sprite-logic-context-v1.json)
checks57 prologue/operand sites and four dispatch-table identities. Native
selectors0/1/2 initialize the original mode8/10h/18h and flags1/2/4.

RAM logic kernels use LODSB direction for source advancement, then an
explicit INCDI by one for the destination regardless of DF. Their alignment-zero
LOOP with count0 means65,536 iterations. Unaligned kernels carry shifted
source bits and perform the original AND/OR/XOR directly against destination
bytes; the trailing neutral mask differs by operation. XOR alignment one
uses AH for its trailing operand; alignments2..7 use DH. Every RAM family
retains its additional source-plane stride adjustment.

The AND and OR hardware paths share the original copy kernels with different
published device mode bytes. XOR has seven distinct unaligned hardware
kernels: initial read into AL, STOSB of AL, another read into AH at the new DI,
and a final MOVDH without the copy tail's destination merge. The adapter
records byteOUT/read/write events against a synthetic flat bus. This preserves
instruction operands and event order without claiming actual EGA latch or
logical device behavior. There were160,104 OUT events,352,010 reads and
330,966 device writes.

All14,304 entry fixtures use two-word arguments with explicit following
guard words. Another9,264 fixtures resume kernels with prepared original
SS frames and raw count/DF/edge variants. Full bus including SS frames,
GPR/BP/CF/IF/DF, writes, budgets and raw return/transfer coordinates match.
Original table bytes remain external. RS260 and the existing mask spans
remain candidate resources, with format interpretation reserved for phase2.

The initial validator omitted the shared95AA cleanup block from its fence.
The next full pass matched but retained a stale four-word coverage label.
Both recipes are archived; the selected pass corrects the label and verifies
minimal argument guards. A shell quoting error launched an unmodified third
attempt, which was stopped and has no receipt. The C build remained unchanged.

BB08 is an explicit verified analysis root; its actual caller and reachability
remain unproven. For all three entries, actual caller bounds, all table/source
writers, ownership, lifetimes, frame/output exclusions, IRQ/reentry and complete
state transitions remain open. No supplied-resource decoding, actual EGA
device, renderer, DOS session, audio, gameplay or fidelity acceptance follows.
CGA remains behind EGA portable code-contract closure.
