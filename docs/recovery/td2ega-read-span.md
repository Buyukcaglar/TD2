# Raw DOS read and text lookahead

`13A8:247C` has a full-SS C contract for a handle, a near DS buffer offset and
a count. It checks current DS handle state, requests DOS3F, and adopts the
full synthetic returned register/BP/DS/ES/CF/IF/DF state. Binary mode returns
without CLD. Text mode clears a flag, saves the returned SI/DI, executes CLD
and scans the returned DS:DX buffer using the returned AX count.

The first byte being LF sets flag4; later LFs do not repeat that test. CR and
Ctrl-Z follow the literal byte loop. AH is set to0D once and is not reset
after later DOS calls. LODSB uses the current DF, while the destination MOV
uses default DS and increments DI by one independently of DF.

Last-byte CR can request IOCTL4400, another3F read and seek4201 with CX/DX
FFFF. IOCTL/seek carry handling and full returned state are preserved. The
lookahead local is SS:[BP-1], but LEA passes the same offset to DOS through
current DS:DX. When DS differs from SS, the written byte and the checked local
are different memory. The native checks demonstrate the resulting difference.

Primary read failure forces AH9 before actual094A; secondary failure retains
the actual returned AH. The compaction count's SUB AX,DX carry also feeds the
shared error branch, so buffer-offset wrap can invoke the mapper after a
successful synthetic DOS read. Normal errors remain distinct from native
budget, adapter, raw-return and pre-RET qualification results.

The C17 `/W4 /WX` build passed3,272 comparisons,128,364 original instructions
and all118 parent/mapper sites. Whole bus, live SS, registers, CF/IF/DF,
requests and counters match. Coverage includes3,884 DOS requests,784 lookahead
reads,188 seek-back requests,1,616 DS=SS cases, four changed mapper returns,
112 changed root returns and24 pre-RET qualifications. All39 native checks
passed separately. The sole known caller next executes ADD SP,6.

RS262 gains this conditional indirect consumer through the actual mapper;
no new resource span or complete codec is inferred. The primary MS-DOS source
pins function numbers. It does not establish a real DOS preservation profile,
INT frames, file I/O, actual caller segment/buffer bounds, writers, storage
lifetime or exclusion. A draft source-line check counted formfeeds as newlines;
the selected review preserves them and uses LF-defined source line numbers.

Historical CPU faults and A20, a DOS session, renderer, audio, complete
state-machine validation, gameplay and fidelity remain separate gates.
CGA recovery remains behind EGA portable code-contract closure. Physical086C
remains unassigned.

Evidence: [comparison](evidence/td2ega-read-span-validation-v1.json),
[context](evidence/td2ega-read-span-context-v2.json),
[native diagnostics](evidence/td2ega-read-span-native-diagnostics-v1.json).
