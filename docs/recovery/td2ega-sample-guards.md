# Conditional byte-source guards

The near entries `49E7` and `4A19` can return before the shared `4A2E`
byte-source path. Both call actual `4D26`, which saves CX on SS, compares
wrapped center-minus-radius and center-plus-radius against signed DS bounds,
and returns ZF=1 on overlap. It restores actual saved CX without changing
those flags. The C bridge uses the frozen interval arithmetic helper and
models the actual SS frames and CF/ZF separately.

`49E7` first tests a center of -400, or -800 when both the `5491` bit and
`37F6` byte select it, with radius5. If it fails, a second test uses +400
or +800 after rereading the bit. Only a successful test reaches `4A2E`.
`4A19` chooses +200 or -200 from incoming BL bit2, with radius7. After
the guard it writes AH=6F, preserving ZF, then either returns the literal
6Fxx value or enters `4A2E`. No boolean return or unconditional sample is
substituted.

[24,320 comparisons](evidence/td2ega-sample-guards-validation-v2.json)
cover both roots, actual `4D26` and the frozen `4A2E` control/setter/ring
family at two load addresses. All156 instruction sites, whole RAM,
registers/BP, CF/IF/DF, root ZF, actual near/far returns and CALL budgets
are checked. [Static review](evidence/td2ega-sample-guards-context-v2.json)
and [59 native checks](evidence/td2ega-sample-guards-native-diagnostics-v1.json)
are separate. The first comparison matched all23,168 cases but lacked two
counter-over-four sites; its exact validator and log are retained. Added
fixtures close that coverage gap without changing C or the DLL.

Actual guard stack words can overwrite the DS bounds when SS=DS. For
example, SP3336 changes the guard decision through the CALL frame, while
SP3338 changes it through saved CX. Tail execution keeps the original SP;
no extra frame is invented for `4A2E`. Inherited conditional writers into
RS270/272/273 remain subject to both the guard and the `4A2E` predicate.

The current graph finds these entries among the initialized targets of
near indirect CALL491D in `4674`; its record selector, table bounds and
all writers remain open. Absence of direct CALLs does not establish
unreachability. Complete caller, shared source/reset/seed, storage lifetime,
IRQ exclusion and core integration remain open. No new resource span,
DOS game session, renderer, audio output, complete state-machine, gameplay
or fidelity acceptance is established. Physical086C remains unassigned;
CGA follows EGA code-contract closure. Complete resource decoding,
Windows gameplay and Amiga recovery have not started.
