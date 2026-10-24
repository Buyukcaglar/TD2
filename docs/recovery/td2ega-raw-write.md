# Raw create, write and close wrappers

[38,400 comparisons](evidence/td2ega-raw-write-validation-v1.json) passed
all58 instruction locations and1,267,824 original instructions. There are
13,168 far returns,18,688 prefixes stopped before a DOS service, and6,544
raw error-call boundaries. The fixtures issue72,016 synthetic DOS requests,
including26,848 writes and20,160 CF-clear write responses.
[Ten native checks](evidence/td2ega-raw-write-native-diagnostics-v1.json)
cover invalid interfaces and adapter failures separately.

7866 and7874 take five SS words: near filename offset, buffer offset/segment
and low/high remaining length. They save BP/DS/SI/DI, write policy0/1 at BP-A
before allocating four more stack bytes, then call DOS create AH3C/CX0. The
handle at BP-8 is initialized only after create succeeds. The optional7874
path still calls close with the existing stack word after create failure;
2,560 fixtures verify that stale-handle close. It is not replaced with a
zero handle or a new early return.

Each write subtracts4000h from caller length words with SUB/SBB before
issuing AH40. Borrow recovers the short tail count and sets both remaining
words to0. The request uses the buffer segment/offset and saved handle.
A CF-clear response advances the caller's buffer segment by400h, even when
returned AX reports a short or zero write. Segment wrap, raw AL halves and
request carry are retained. Close AH3E errors are ignored; the epilogue sets
AX0, discards its locals and restores DI/SI/DS/BP before plain farRETF4.

Synthetic service responses vary DS, BP, registers and flags, and may mutate
shared SS parameters and saved words. An explicit shadow frame tests returned
BP changes. The complete bus, request order, caller length/segment updates,
saved-frame restoration, GPR/BP/CF/IF/DF and exact return/prefix state match.
The adapter preserves SS/SP/CS control; Unicorn's INT hook and the native
adapter omit real DOS interrupt-entry/return frames. No real file is created,
written or closed.

Policy0 errors restore DS from the saved SS word, push the current near
filename and format offset6808, then far-call16A7:0002. The comparison stops
at that original callee entry with its actual frame and prepared words. Native
outcome1 reports the same boundary. FN-EGA-000348's handler contract is still
pending; this receipt establishes neither its body, non-returning behavior,
normal return convention nor whole error-path integration. Two prepared words
do not establish its source variadic signature. No handler return is invented.

The [static review](evidence/td2ega-raw-write-context-v1.json) checks32 operand
sites and two direct caller candidates. The pinned Microsoft source corroborates
historical CREAT/CLOSE/WRITE service identifiers, not the deployed DOS version
or actual runtime behavior. Original filenames, format text and buffer bytes
remain external. Actual caller/source capacity, ownership, lifetimes, all
writers, IRQ exclusion, error-handler and complete state/core integration
remain open. Resource decoding, actual device/render/audio/DOS-session,
gameplay and fidelity gates remain separate. CGA stays behind EGA portable
code-contract closure.
