# Fallback initializer inside the EGA executable

`06C9:5F64` now has a C contract for this path in `TD2EGA.EXE`. It sets
the initial-DS byte5E6E, masks the physical0410 word through0040:0010,
and invokes synthetic BIOS INT10 with AX0004. The full returned register,
BP, DS/ES, carry and IF/DF state is adopted. The body does not save BP;
its caller subsequently writes through the returned BP.

Two byte OUTs precede a12-iteration loop over current DS:[5E70+BX]. Each
index OUT to3B4 occurs before the corresponding table read and value OUT
to3B5, so intervening bus mutations remain visible. CLD then forces forward
direction for16,384 word effects at B800:0000..7FFE, exactly32 KiB under
the selected raw RAM adapter. A final OUT to3B8 precedes the actual saved
DI restore and far return.

The typed device adapter preserves CPU state and owns each little-endian
word effect. BIOS return state is separate from that device response.
All16-bit SP inputs retain their body effects; SP>FFFC produces the same
explicit pre-RET qualification result used by the plane-fill contract.
Historical CPU and exception behavior remain unqualified.

The C17 `/W4 /WX` build passed388 comparisons,2,457,936 original
instructions and all40 sites. Full bus/SS, registers/BP/CF/IF/DF, BIOS
requests, port/device requests and counts match. Coverage includes364
synthetic BIOS calls,6,684 byte OUTs,2,424,904 word writes,14 changed bounded
root returns and24 pre-RET qualification cases. Thirty-three native checks
and the static mask/address proofs remain separate. The actual caller's
arithmetic flags pass through the6A17 setter and are replaced by ADD SP,4.

RS277 records only the initialized12-byte port-value candidate at5E70..5E7B.
Its runtime DS binding after BIOS, writers, field units, controller identity
and hardware effects remain open. Physical0410 is distinct from the086C
external-word read; no timer units or frequency are assigned.

This is EGA executable recovery. CGA edition unpacking and analysis remain
behind EGA portable code-contract closure. Actual BIOS/INT frames, controller
and device hardware, renderer, caller stack/BP/IF domains, storage, exclusion
and core integration remain open. No DOS session, audio, complete state-machine,
gameplay or fidelity acceptance is established.
