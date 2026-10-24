# Two control compositions

`06C9:5A6F` and `44EA` are near entries with no SS arguments. They use
the actual frozen `control_bus` C bodies, with full returned registers,
CF/IF/DF and memory effects. Every outer and nested near-call frame is
literal. Direct tail jumps let the helper execute the root RET; no extra
return operation is invented. Minimum root SP20 preserves helper SP18
and nested frame SP16. Outer-call and inner4612-call budgets are separate.

`5A6F` clears2F56/33B2, calls4588 and44D8, then reads byte33D4. Value4
increments33CE by3 with an unsigned100 guard. Value1 subtracts25 from52CC
and uses a signed comparison with33D0; other values add25 and use the
opposite signed condition. The common path adds33D2 to33CE, increments BX
twice, stores both words and applies an unsigned280 guard. The source clear
of2F56 is not an exclusion guarantee: an actual SS call frame can overwrite
it and enable the nested4612 product.

`44EA` preserves its byte guards, indexed33BF view, special33B7 value8,
fixed DX1600/800/400 tail paths, and ordinary4588/45BF calls. Its action
path clamps a byte-derived table2419 index to80, multiplies AL by DH,
shifts five times, calls45BF and jumps to4612. The later nonzero336F branch
at4580 cannot execute from this entry under serialized RAM: the early
nonzero guard bypasses the action path, which has no336F write or call
before the later test. This disposition is separate from IRQ exclusion
or a globally dead-code claim.

The C17 `/W4 /WX` build passed 40,928 comparisons, 827,434 original
instructions and all 162 feasible sites in the 163-site fence. Full bus/SS,
GPR/BP/CF/IF/DF, control and counts match. Coverage includes 23,912 outer
calls, 13,176 nested4612 calls, 6,176 minimum-SP20 cases, 1,104 altered
outer returns, 516 altered inner returns and 156 altered root returns.
Raw targets are exposed after actual RET and never followed. Fifteen native
diagnostics separately include the cleared flag re-enabled by a call frame.

The direct callers are403B:4124 and403B:40F3. The latter's arithmetic
status flags are replaced by the later SUB. `5A6F` status flows through
the403B epilogue and still needs complete caller/callback liveness review.
Full403B, other FLAGS, DS/SS binding, all writers, raw table/field bounds,
ownership, lifetime, IF/DF context and interrupt exclusion remain open before
core integration. No physical units, progression meaning, DOS session,
renderer, audio output, complete state-machine, gameplay or fidelity is
established. CGA and later resource/Windows/Amiga gates retain their order.
