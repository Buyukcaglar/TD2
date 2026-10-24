# Raw record projection

`06C9:0201` clears17 words through REP STOSW, sets ES to current DS and
clears DF. It copies raw fields and processes two record groups with cached
base words. Both loops are do-once, increment SI by8 and reread the current
DS5354/5356 bound after every record. Zero counts still process one record;
unaligned high bounds can cycle after SI wraps. Capacity remains unproved.

Each relative high-word SBB is followed immediately by JGE, retaining its
signed SF/OF relation and low-word borrow. A negative difference receives one
period addition. An unsigned high result at most60 admits three word stores
in an eight-byte output slot. The fourth word is left untouched. DI continues
across both groups. Input, output and live bounds retain shared bus identity.

Final paired projections reuse the cached base, and the final SHL supplies
returned carry. BP contains the last record word; it is not saved by this root.
The actual SS far-return words are read after all stores. Both real callers
immediately call2089, whose entry XOR AX,AX kills arithmetic status flags.
Whole caller state and exclusion remain open.

The C17 `/W4 /WX` build passed17,364 comparisons,3,588,656 original
instructions and all106 sites. Full bus/SS, GPR/BP/CF/IF/DF, control and
write counts match. Coverage includes8,684 DS=SS cases,3,072 SP0 cases,
896 changed far returns and12,270 before-record budget prefixes. Fourteen
native diagnostics and655,360 static SBB boundary checks are separate.

No units, complete record schema, caller capacity, writer/ownership/lifetime,
interrupt, core, resource-fed or runtime acceptance follows from this packet.
No DOS session, renderer, audio output, complete state-machine, gameplay or
fidelity gate is established. CGA remains behind EGA contract closure.
