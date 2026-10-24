# Raw field controller

`06C9:5880` is a near entry with no SS arguments or saved-register prologue.
Six possible near calls compose the frozen `5299`, `5C5A`, `52FD`, `5334`
and `535B` C bodies. Their actual SS frames, register clobbers, ordered
memory writes and near returns feed the parent. Root minimum SP34 preserves
the frozen `52FD` minimum SP32.

The first call uses byte-MUL factor255 and raw DS table views. Its saved
first byte becomes DS:33BE. The second uses divisor1600; AL becomes
DS:3376. Two guarded ratio calls use record words selected by raw origins.
The first result is stored to DS:333E; the second can update a threshold
through `5334`. The table views overlap raw globals, so their storage is
shared throughout the comparison. No independent table allocation, valid
index domain, physical unit or simulation meaning is inferred.

`535B` supplies raw DX/CX. Byte33B7 and byte3376 can force CX200. The
parent's subtraction carry, unsigned thresholds20/1600 and zero3344 check
select writes to byte336C; one carry path retains its old byte. The final
signed comparison moves `52CC+40` toward CX by44, clamps after the wrapped
word operation, subtracts40 and stores52CC. Final CF comes from that SUB.

The C17 `/W4 /WX` build passed 22,432 comparisons, 1,449,096 original
instructions and all 207 feasible parent/child sites. The remaining fenced
site, `52FD:5303`, cannot execute from that entry because adjacent JLE/JG
branches consume unchanged flags and exhaust their domain. This is a
bounded disposition, with no claim that the bytes are globally dead.

Full memory, actual SS, GPR/BP/CF/IF/DF, control coordinates, writes and
call/iteration counts match. Coverage includes 42,698 actual near calls,
4,608 minimum-SP34 cases, 11,216 DS=SS cases and 1,024 raw child returns.
Changed return targets are exposed after actual RET and never followed.
Twelve native interface diagnostics are separate. No leaf return-value
mock or excluded SS region was used.

The direct caller is `403B:40F0`, followed by `44EA`. Its full body and
FLAGS requirements, all writers, table/record bounds, ownership, alias
lifetime, interrupt exclusion and core integration remain open. No actual
DOS session, renderer, audio output, complete state-machine validation,
gameplay or fidelity is established. CGA remains behind EGA portable
code-contract closure; complete resource decoding, Windows-host gameplay
and Amiga recovery retain their later gates.
