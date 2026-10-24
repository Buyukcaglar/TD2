# EGA state-message and shared helper contracts

2026-10-14. Eleven entries at06C9:36E0/3713/371F/372B/3737/3743/374F/375F/
3788/3F0D/5C98 have one [C17 export](evidence/td2ega-state-messages-build-v1.json)
and [7,140 comparisons](evidence/td2ega-state-messages-validation-v1.json).
All122 fenced instruction locations execute across two load bases, equal and
independent DS/SS, returned DS changes and explicit service flag profiles.
Graphics, text, formatter, wait and input leaf bodies use ABI mocks.

3788 returns with a plain near RET, popping2 bytes. The other entries use
plain far RETF, popping4 bytes. 3788 calls actual5C98, then passes15/0 to7A82.
Its first drawing call leaves five argument words live while the second call
pushes five more; one ADDSP20 cleans both. The first draw retains returned DI.
5C98 passes offsetAF54 and currentCS as a far pointer to7D5E.

36E0 similarly retains the first two text argument words during a second
text call and cleans eight bytes. Shared text calls pass a near currentDS
pointer and0032. 3713 increments8658; 371F..3743 increment536C, with word wrap
and INC preserving CF. 374F returns early when9410 is nonzero. 375F tests8424:
one selects2F27, otherwise formatter13A8:2A3C receives destination2F20,
format2F24 and the raw counter, followed by text2F13. This does not prove the
formatter output fits before2F24, nor establish the caption encoding.

The shared tail passes raw distance30 to7A55, then executes actual3F0D.
3F0D loops on69FE untilAX0, passes raw distance40 to7A55, and tests currentDS
8A9A. Zero additionally calls6A3B and6A6A with raw distance0708. These values
have no assigned time units. Actual keyboard, callback, counter and IRQ
behavior remain separate obligations.

The native API exposes virtual SP and exact live argument words. Services
must preserve SS/SP/control frames/caller argument words and use supplied
arguments rather than reading unmaterialized native stack frames. Code,
data and live frame views must be separate, with nonwrapping stack offsets.
Current DS and modeled CF/IF/DF propagate through leaf responses. Other
arithmetic flags are outside this interface.

[Five native-only diagnostics](evidence/td2ega-state-messages-native-diagnostics-v1.json)
cover invalid entry/frame, zero budget, continuous input and a rejected leaf.
They are excluded from original comparison totals and error equivalence.

Text16AB:000C passes the near pointer to13A8:29B4 before positioning/drawing.
Formatter2A3C constructs near BP-relative frame/variadic pointers, then uses
DI-relative accesses that default to DS. Real body integration therefore
needs DS=SS or proved corresponding views; independent DS/SS message fixtures
with an opaque formatter do not establish this precondition. Output bounds,
formatting semantics and actual caller states remain P1 obligations.

No DOS game session, renderer/audio output, complete state-machine validation,
Windows-host gameplay or gameplay/fidelity acceptance follows. CGA remains
behind EGA portable code-contract closure. Full resource decoding and Amiga
recovery remain unstarted.
