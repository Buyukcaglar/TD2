# Conditional pair-update controller

`FN-EGA-000399` (`06C9:595F`) is a near entry with no SS arguments.
It conditionally calls the frozen `5A25` C body three times, using raw
pairs at DS:52C8/52D0/52D8 and words DS:334A/334C/334E. Returned CX is
stored even on a child path that leaves CX unchanged. Each returned CF
feeds the following JB directly through a flag-preserving MOV.

The first taken branch tests the sign of BX. The second and third test
the sign of CX after OR. Their literal flag, pair, counter and field writes
retain source order. In particular, `5A25` writes the high destination word
before rereading the low source word. Negative parent paths subtract two
from DS:52DA or add `0500` to the loaded word. No collision interpretation,
physical units or record schema is assigned.

The parent retains child register clobbers and uses seven plain near RET
sites. Actual SS CALL frames and returns are compared, including changed
child and root targets, which are exposed after RET and never followed.
Minimum root SP18 preserves the frozen child minimum SP16. Native CALL
budgets stop before pushing the next frame.

The C17 `/W4 /WX` build passed 20,464 comparisons, 614,140 original
instructions and all 96 parent/child sites. Coverage includes all seven
root returns, 16,874 actual near calls, 4,096 minimum-SP18 cases,
10,272 DS=SS cases, 24 raw child returns and 120 altered root returns.
Full memory, SS, GPR/BP/CF/IF/DF, control coordinates and write counts
match. Twelve native interface diagnostics are separate.

The single direct caller is `403B:411A`. Its next CMP at `411D` replaces
all arithmetic status flags before a conditional read. The preceding
`4D3F` return also meets a full status setter at the `595F` entry XOR BP,BP.
Within this controller only CF is consumed from `5A25`; later signed
branches first execute OR BX or OR CX. The frozen child's CF interface
therefore supplies the status flags this parent actually needs. IF and DF
remain live caller/context obligations.

The complete `403B` body, DS/SS setup, all writers, storage bounds,
alias lifetime, interrupt exclusion, CPU-profile binding and core integration
remain open. This is bounded source/build/isolated-instruction proof, with
no complete state-machine, DOS session, renderer, audio output, gameplay
or fidelity acceptance. CGA remains behind EGA portable code-contract
closure; complete resource decoding, Windows-host gameplay and Amiga
recovery retain their later gates.
