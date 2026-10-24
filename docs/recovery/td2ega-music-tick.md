# EGA PC Speaker music callback

2026-10-13. `06C9:75EA`, `FN-EGA-000362`, now has a
[C17 build](evidence/td2ega-music-tick-build-v1.json) and
[13,346 original/native comparisons](evidence/td2ega-music-tick-validation-v1.json).
All 185 instruction locations in the conservative fence execute across the
fixtures. This is a serialized code contract with synthetic source memory and
port services. It establishes no audible output, IRQ delivery or clock rate.

The callback requires mode5EFB=3. Other modes clear5EFC/65D2 and clear port61
bits0/1. A pending65D2 clears that flag, sets port61 bit1, then reads a
three-byte song record through65F5:65ED. Its word selects an event offset;
its byte adds to65D5 modulo65536 for the table index base. The song-record
cursor advances by three. An active callback without a pending record
continues the existing duration/pitch state. None of these counters is given
a wall-clock unit.

Event pairs advance65E9 by two before interpretation. Nonnegative first
bytes are notes/rests; bytes80..FA enter the silence path. Negative commands
FB..FF use the five original words atCS766C, with these effects:

| Byte | Target | Effect |
| --- | --- | --- |
| FF | 76B1 | Copy restart65F1 to song cursor65ED and read a song record |
| FE | 7678 | Zero-extend the operand into65D3, then read another event |
| FD | 7683 | Copy14 words from voicebase+32*operand to principal6609..6624 |
| FC | 761E | Read the next song record using current65ED |
| FB | 76BA | Clear flags5EFC/65D2 and cursors65ED/65EF, then RETF |

FB does not immediately write port61. The ordinary silence path does. A
command-only cycle or an impossible pair of pitch bounds can fail to return;
the native API's explicit budget reports diagnostic3 instead of inventing a
successful original return. [Four native-only diagnostics](evidence/td2ega-music-tick-native-diagnostics-v1.json)
check that boundary and argument/adapter failures separately from parity.

A zero note multiplies the low byte of65D3 by the full duration byte. A
nonzero note multiplies it by the duration's low seven bits, then divides
the result into on/rest counters according to the high duration bit and
6609 shift byte. The comparison profile uses x86 five-bit masked SHR counts;
an unmasked early-8086 CPU profile is not admitted by these fixtures. Note
indexes and modulation indexes read wrapped words at663B+2*index, preserving
aliases to other group data. This includes possible reads of byte-ring fields;
the callback does not write the ring cursor or buffer through those indexes.

The on counter decrements before the modulation and pitch work. On reaching
zero, it clears port61 bit0 and returns. The rest counter decrements and
returns; a zero rest resumes event processing. Modulation reloads a countdown,
increments its index, masks it through660F and reads a byte at6611+index
before selecting a new divisor word. Pitch changes use wrapped arithmetic
with signed bounds. Limit mode either reverses the signed direction byte and
retries, or resets the pitch offset to zero. Port42 receives low byte then
high byte; the native API records requests and performs no device I/O.

The voice command temporarily changes DS to65F7, establishes relocated
principal ES, copies forward with CLD and restores principal DS and DI. The
source offset advances modulo65536 per word; ordinary word accesses retain
their adjacent byte when starting atFFFF. Source/group overlap is preserved
by the shared bus, including forward-copy aliases and subsequent field reads.
IF is unchanged; DF becomes zero only when this copy executes. AX/BX/CX/DX,
SI/DS/ES and DF are exposed; BP/DI/SS and the far-return frame are checked.
Data writes must remain separate from executing code and live stack.

Main binds the raw `voices.bin` pair through75C8 and the song pair through758A.
The registered supplied VOICES.BIN identity is two bytes. Even operand zero
requires a28-byte source read, so that file alone does not bound the voice
command. Command reachability from supplied songs, allocation adjacency,
initialized bytes beyond the file and any intended edition/profile explanation
remain named resource-fed phase2/3 obligations. This review does not decode
the corpus or infer that the command executes in an accepted game session.

Actual callback installation/removal and nesting, all platform profiles,
source lifetimes, complete state-machine recovery, audio output, gameplay and
fidelity remain open. CGA stays behind EGA portable code-contract closure.
