# Inherited-frame block adjustment

`13A8:28C0` is a near helper using its caller's BP frame. It reads the
segment key from actual SS[BP+0E], starts SI at DI and scans four-byte rows.
`2852` owns the BP frame and sets DI to6D2A. Its calls at286A and2883
immediately consume returned carry; the second saves/restores SI on SS.

The helper retains size-addition carry, the6D24 capacity shortcut, and
ADD15/RCR/three-SHR rounding through a17-bit value. This equals ceiling
division by16 even at sizeFFFF, where the result is4096. Its first-row
path adjusts the request using6D9B. The pinned MS-DOS source identifies
AH4A as SETBLOCK. Tests use a synthetic boundary with full returned state
and bus mutations; no DOS memory operation or real INT frame is exercised.

After service success, the original compares returned SI and DI, which
can replace returned carry. It conditionally updates current-DS6D24, then
exchanges DX/AX and the actual DS[SI] word before setting DX from CX.
Neither returned DS/SI nor the near-return word is cached. The caller's
real register-preservation and storage assumptions remain open.

The C17 `/W4 /WX` build passed15,824 comparisons,528,076 original
instructions and all39 sites. Full bus/SS, GPR/BP/CF/IF/DF, request ABI,
control and instruction write counts match. Coverage includes1,888
synthetic services,7,912 DS=SS cases,4,608 SP0 cases,1,014 changed near
returns and10,160 before-record/service boundaries. Nineteen native
diagnostics and65,536 static rounding checks are separate.

RS274 records the initialized80-byte raw metadata candidate6D2A..6D79,
twenty rows under the observed2852 DI value. The6D7A cursor,6D24 capacity
and6D9B base lie outside it. Known helper and parent writers are recorded;
complete writers, valid domains, storage ownership and lifetime remain
open. This is no external media format or complete resource decoding.

No DOS session, renderer, audio output, complete state-machine, gameplay
or fidelity acceptance is established. Core integration remains pending.
