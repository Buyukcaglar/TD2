# Runtime exit request and actual helper chain

`FN-EGA-000261` (`13A8:0599`) saves BP and runs two actual near060D
walks with fixed SI=DI7086. It then executes actual066E and its message
chain. The full AX result controls a word test at SS:BP+6: only nonzero
AX plus a zero argument word writes00FF. This differs from testing AL
or checksum AH alone. An argument word FF00 is nonzero, yet its final
low exit byte is zero.

The helper initializes CX15/BX5, tests bit1 in currentDS[BX+6DA4], and
requests DOS AH3E for flagged entries. Returned BX/CX/DS/BP/CF/IF/DF feed
the next INC/LOOP and read. A fixed 15-iteration bound requires platform
preservation of the counters. Raw service-clobbered loops are retained
with diagnostic budgets. It then executes actual near05E0 cleanup, reads
the exit word through returned BP, sets AH4C and prepares INT21.

The clean build-v1/comparison-v1 passed 45,344 cases, executing 11,730,328
original instructions across 124 sites. The fence has131 sites: six060D
body sites are unreachable under these fixed empty spans, and05DE is
observed as a prepared boundary without executing its INT. The complete
060D unit independently covers all nine helper sites. No site is silently
discarded or declared globally dead.

Full memory including nested near/far frames, GPR/BP/CF/IF/DF, requests and
control coordinates are compared. There are 10,672 prepared exit requests,
25,744 budget prefixes, 8,928 raw child returns, 169,096 synthetic DOS
services and 15,632 callbacks. Synthetic callback RETFs are counted
separately. The suite includes 2,048 all-byte checksum/exit-word compositions,
2,304 minimum-SP80 cases and 1,280 cases with more than fifteen close-loop
iterations. Twenty native profile, stack, budget and adapter checks are separate.

The pinned DOS reference defines AH4C as termination of the current process
and transfer to its invoker. The comparison stops before05DE at that prepared
request. **No actual DOS process exit or session occurs.** No root RET or
epilogue is invented; BP save, argument and far frame remain live. Conservative
disassembly fallthrough into05E0 after the exit instruction is not followed
under the documented termination contract. The earlier near05E0 call is
fully executed and compared.

Two direct caller candidates, source/key/bounds/other-FLAGS requirements,
callback targets and all writers/lifetime/exclusion remain open before core
integration. Original message data remains external. No renderer, audio,
complete state-machine, gameplay or fidelity gate is established. CGA remains
behind EGA portable code-contract closure; full resource decoding remains pending.
