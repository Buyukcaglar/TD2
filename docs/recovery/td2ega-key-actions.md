# EGA installed key-action callbacks

2026-10-13. Six noargument RETF entries645A/646F/6488/64C7/6508/6518,
`FN-EGA-000404..000409`, share one typed native entry with an explicit action
selector. The [C17 build](evidence/td2ega-key-actions-build-v1.json) and
[12,288 comparisons](evidence/td2ega-key-actions-validation-v1.json) exercise
all71 instruction locations in the six fences. External UI bodies are ABI
services. No display/input/device session executes.

| Entry | Writes before external call | External target and arguments | After return |
| --- | --- | --- | --- |
| 645A | 6CFC=1,5EFE=1 | 1769:000E, no arguments | 5EFE=0 |
| 646F | 6CFC=0 | 16FC:0220,603C/8/0 | Return |
| 6488 | Toggle mode bit0 as below | 16FC:0220,6029 or6032/8/0 | Return |
| 64C7 | Toggle mode bit1 as below | 16FC:0220,6016 or601F/8/0 | Return |
| 6508 | 5EFE=1 | 16FC:0358, no arguments | 5EFE=0 |
| 6518 | 5EFE=1 | 16FC:007C, no arguments | 5EFE=0 |

The three-word calls push0,8,text then perform a far call. The callee's first
argument is the near text offset; the caller removes six argument bytes after
RETF. The text remains in the external original image. The native service
receives the original relocated code target, arguments and modeled registers;
it performs no presentation itself.

Enabling effects ORs mode5EFB with1. Disabling effects ANDs it with2, clearing
all other bits, then clears5EEE and5EFC. Enabling music ORs the mode with2;
disabling music ANDs with1 and clears the same active segment/flag. These are
literal shared-state effects, without substituting independent host booleans.
All256 incoming mode bytes are tested, including high bits.

Guarded calls overwrite5EFE with1, then with0 on normal return. They do not
restore its previous value. The final clear uses returned DS; there is no
DS restore in these callbacks. Fixtures let the external service change DS,
ES, SI, DI and IF/DF and write both old/new guard locations, checking the exact
clear address and partial state. SS/BP and control-frame integrity are adapter
preconditions; incidental arithmetic flags are outside this packet.

[Four native-only diagnostics](evidence/td2ega-key-actions-native-diagnostics-v1.json)
keep invalid-action/flag and rejected-UI prefixes separate from original
equivalence. A rejected guarded service leaves5EFE=1 in its original segment;
no successful original return is claimed for that diagnostic.

Timer61BF skips callback work when5EFE is nonzero, but still performs its
earlier counter/old-vector work. The key callbacks' publication order does not
alone prove complete interrupt exclusion, nested scheduling, nonlocal UI
exits, resource lifetimes or segment-preserving real UI behavior. The six
installer key values and far dispatch frames are recorded separately in the
key-binding/dispatcher packets. Actual UI bodies, IRQ/caller/state ownership,
renderer/audio output and gameplay/fidelity remain open. CGA stays behind
EGA portable code-contract closure.
