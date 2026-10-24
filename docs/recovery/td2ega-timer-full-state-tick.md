# Published timer caller through the whole403B controller

18 October2026. [25,024 supplemental comparisons](evidence/td2ega-timer-full-state-tick-v2.json)
match26,191,488 original instructions under actual61BF->6269->403B. The
[corpus review](evidence/td2ega-timer-control-bus-context-v1.json) verifies that
the complete previous403B case generation is unchanged as an AST: all eight
stable code forms and two relocation bases remain. ParentSP is mapped into
68..FFE0 and actual403B entrySP is parentSP-22; endpoint fixtures are adjusted
to this caller's admitted stack domain. Equal/distinctSS and existing state
aliases are retained within that domain.

Original3FD9/601C/614C executes16 times to publish6269 then403B and a sentinel:
3,376 instructions/78 sites. These source-only producer counts are separate
from native comparisons and do not accept native startup or IRQ delivery.
The actual row bytes survive fixture changes. Actual C bodies execute both
callbacks; original bodies execute actual far returns and handlerIRET where
admitted. Partial or raw child returns stop without being followed.

All80 root sites/11nearCALL sites are exercised, with97,472 root calls,
448 actualPUSHF words,192 actual780E entries and256 nonlocal585A/B exits.
The whole-caller corpus exercises1,309 of3,024 union sites; separate unit
coverage is retained without promoting it into complete caller path coverage.
Full1MiB RAM, GPR/BP/CF/IF/DF, defined parentFLAGS, independent CPU/modeledINT
writes and ordered ports match. Unexposed child arithmetic bits useF72B at
prefixes; actual callerADD/CMP regains defined arithmetic bits.

Of25,024 cases,13,984 retire the handler,1,696 report raw returns,8,384 stop
at budgets and960 preserve unknown-target prefixes.403B itself retires14,144
times;160 of those subsequently produce a raw parent return. The distinction
is retained.2,304 keycallback ABI-effects/genericRETF operations remain
explicit models; they do not establish the corresponding callback bodies.

FN-EGA-000003 now has consumption witnesses under this actual published caller.
Ring reset, every writer/valid index domain, source lifetime, IRQ/nesting and
exclusion remain required before core admission. No RNG purpose is assigned.
Native helper totals exclude these25,024 supplemental cases. No full native
startup, real DOS session/devices, renderer/audio output, complete state-machine,
gameplay, fidelity or P1-GATE acceptance. CGA remains behind EGA closure.
