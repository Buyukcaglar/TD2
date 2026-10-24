# Raw handle-seek wrapper

`13A8:225E` takes four SS words: handle, offset low/high and raw mode.
It saves BP and reserves two SS words. An unsigned handle-limit guard
rejects with AX0900/CF1. A negative offset and zero mode reject with
AX1600/CF1. These paths use the actual frozen `094A` mapper.

Other negative offsets first query through DOS4201. Its returned carry
is tested. With mode bit2 clear, ADD/ADC combines the returned position
with reread SS arguments and JNS tests only the resulting DX sign bit.
With bit2 set, the returned DX then AX are saved in actual SS locals,
and DOS4202 runs with DX copied from returned CX. That call's carry is
ignored before ADD/ADC/JNS. A negative result reloads the actual locals
and invokes DOS4200; its carry is also ignored before forced AX1600/CF1.

The final seek loads actual SS words into DX/CX and the raw mode byte
into AL, with AH42. On success it clears bit2 at returned DS:[BX+6DA4]
and preserves returned AX/DX. It does not replace AX with zero. The
historical MS-DOS primary source identifies service42 as LSEEK; no host
seek enum or actual DOS operation is inferred.

Full service-returned GPR/BP/DS/CF/IF/DF and bus writes feed subsequent
instructions. SS/SP/CS control is preserved by the synthetic adapter.
The shared tail uses actual mapper near frames, word CWD on error,
MOV SP,returnedBP, POP BP and plain RETF. Minimum root SP24 preserves
the mapper's SP16 after BP save, locals and near frame. Raw mapper/root
targets are exposed after actual RET and never followed.

The C17 `/W4 /WX` build passed 26,576 comparisons, 687,030 original
instructions and all 74 sites. Full bus/SS/GPR/BP/CF/IF/DF, service ABI,
control and counts match. Coverage includes 11,480 synthetic DOS calls,
584 restore calls, 19,908 mapper calls, 8,192 minimum-SP24 cases,
2,944 raw mapper returns and 3,760 altered root returns. Seventeen native
interface diagnostics are separate. Synthetic callback writes are counted
separately from recovered-instruction writes.

Five direct calls belong to `0C4E` and `2AD8`: 0CF5, 0DB4, 2AEB,
2B15 and 2B2D. Each immediately executes ADD SP,8, cleaning the four
arguments and replacing arithmetic status flags. Complete parent bodies,
record/handle/offset producers, all writers, storage bounds, ownership,
lifetime, IF/DF context and interrupt exclusion remain open before core
integration. No DOS session, rendering, audio output, complete state-machine
validation, gameplay or fidelity is established. CGA stays behind EGA
portable code-contract closure; later resource, Windows-host and Amiga
gates remain unchanged.
