# Inherited write span and nonlocal far return

`13A8:2600` now has a C contract for its actual inherited BP/DS/DX/DI
context. It saves AX/BX/CX, forms the raw word span DI-DX and skips DOS
when that span is zero. Otherwise AH40 retains AL, the handle comes from
actual SS:[BP+6], and the synthetic DOS service can return full register,
BP, segment, IF/DF and bus state.

CF0 adds returned AX to the actual SS count at BP-2. Any nonzero AX then
returns through the near frame, restoring actual saved AX/BX/CX and putting
actual returned DX in DI. A short nonzero write is accepted without retry.
CF1 or AX0 selects a different exit.

That path executes ADD SP,8, discarding the three saves and the near-return
word. The addition replaces the DOS carry. Its carry is set for entry SP
values0..5,FFFE andFFFF under the serialized16-bit stack profile; all65,536
values were checked statically. Stack carry selects AH09. Without stack
carry, the code tests current handle flags and a current-DS byte1A. A match
clears carry and can preserve a raw DOS error AX through the far exit.
The other path selects STC/AX1C00. These source quirks are retained.

The shared exit loads SP from actual SS:[returned BP-8], restores SI/DI,
and reaches the enclosing2558 far epilogue. If carry is set, it calls the
actual094A mapper before returning AX/DXFFFF. The mapper's OR AH,AH itself
clears carry, so final CF does not identify a DOS error. Its byte6DA0 and
word6D95 stores can overwrite its actual near-return word; a changed target
is exposed after RET and never followed.

The API reports whether the root operation was a near return or this
nonlocal far return. The actual094A body and near frame are included inline
so the standalone mapper API's SP16..FFE0 fixture restriction is not borrowed
for this inherited stack context. Only its AH09/1C path is reachable here:
eight of21 mapper sites. The13 exclusions are entry-specific; standalone
094A covers its complete body.

The C17 `/W4 /WX` build passed13,440 comparisons,235,412 original
instructions and all51 feasible sites in the64-site family fence. Full
bus/SS, GPR/BP/CF/IF/DF, requests, counters and control match. Coverage
includes7,040 synthetic DOS writes,3,024 stack-carry paths,576 byte1A exits,
60 changed mapper returns and880 changed root returns. Twenty-six native
checks and the static stack proof remain separate. Known near caller paths
replace arithmetic flags before consuming them; all three enclosing far
callers immediately execute ADD SP,6.

Whole2558, its fatal callbacks, all writers, actual frame/storage domains,
capacities, ownership, lifetime, interrupt exclusion and core integration
remain open. Synthetic services omit real DOS/INT frames; historical
CPU/A20 behavior remains unqualified. No DOS session, renderer, audio,
complete state-machine, gameplay or fidelity acceptance is established.
CGA remains behind EGA portable code-contract closure.
