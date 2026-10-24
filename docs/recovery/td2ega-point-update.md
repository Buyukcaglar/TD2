# Cached old and new point calls

`06C9:3AB8` is a near entry with SI/BX/DX inputs. It subtracts3B51 from
signed SI, clamps a negative mathematical difference toFFE0, then performs
five arithmetic shifts. All65,536 inputs produce eitherFFFF or0..549.
The old word comes from current DS:[BX+2F50]. Equality returns immediately;
otherwise the new word is committed before any call or device effect.

The body prepares the new point's three SS words first, retaining the
incoming color, then optionally calls actualBA3C to erase a nonnegative old
point with color0. It tests actual returned SI before optionally calling
BA3C on the remaining new-point frame. Child writes can change saved SI,
arguments, plane selectors, row state and return words between calls.
Both children share CALL and device-event limits. The final ADD SP,6
sets CF for initial SP0..5 and ZF for SP0. Plain near RET consumes two bytes.

The C17 `/W4 /WX` build passed9,216 original-instruction comparisons:
567,096 executed instructions and all90 sites. Whole memory, registers/BP,
CF/IF/DF, root ZF, device requests, counters and control match, including
96 raw child returns,120 changed root returns and288 child pre-RET
qualifications. Forty-three native checks and static normalization/SP proofs
are separate. The child C and its selected evidence remain unchanged.

The three known calls in3A91 use cache offsets0/2/4, source words52CA/52D2/
52DA and colors0C/09/0E. This supports a minimal six-byte initialized cache
view, RS281, whose initial bytes are zero and intersect no relocations.
It establishes neither a total capacity nor complete writers or lifetime.
RS279 gains a conditional indirect mask consumer through actualBA3C.
Caller arithmetic flags are replaced by the next3AB8 entry or3945 CMP.

Actual caller DS/SS, coordinate domains, all writers, capacities, ownership,
lifetime, interrupt exclusion and core integration remain open. Device
comparisons use a raw RAM adapter; real EGA latches, rendering, a DOS session,
audio, complete state-machine, gameplay and fidelity are unaccepted. CPU/A20
behavior and physical086C semantics remain unqualified. CGA stays behind EGA
code-contract closure; full resource decoding has not started.
