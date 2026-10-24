# Raw radix text conversion

`FN-EGA-000330` (`13A8:29D0`) takes three SS words: value, near destination
and radix. Decimal radix ten uses word CWD and can emit a minus sign.
`FN-EGA-000331` (`29EC`) takes four words: low value, high value, near
destination and radix. That entry disables the sign-prefix path, including
for decimal values with the high bit set. These are machine interfaces;
source C prototypes and caller value domains remain unassigned.

Both entries execute the actual shared body at `2BBC`. PUSH DS/POP ES and
CLD precede digit generation. Two unsigned DIV instructions implement a
raw long-division step. Radix zero faults; radix one can repeat indefinitely
for a nonzero value. Radices above 36 retain the source's byte digit
arithmetic and wrapping additions. No range clamp or error text is added.

After the NUL store, reversal executes at least once, using wrapped SI/DI
and unsigned `CMP (SI+1),DI`. A host reversal assuming no address wrap
would differ. Actual SS saves, arguments and return coordinates can alias
output. POP AX reads the actual saved destination; DI/SI/BP restore from
SS, and plain RETF consumes four frame bytes. Raw altered targets are
exposed after RET and never followed by the harness.

The clean C17 build passed 85,760 original-x86 comparisons, 7,053,424
instructions and all 71 sites. Full bus, real SS saves/frames/arguments,
GPR/BP/CF/IF/DF and control match. Coverage includes 5,120 minimum-SP32
cases, 42,880 DS=SS cases, 5,952 radix-one nonprogress prefixes, 4,832
zero-DIV prefixes, 34,560 cases above radix 36 and 5,796 altered far
returns. Twelve native interface diagnostics are separate.

Fault comparisons stop before DIV and exception delivery. Successful DIV
FLAGS are undefined and unadmitted; subsequent defined arithmetic, OR and
CMP establish modeled CF at admitted prefixes and return. Native budgets
before digit/reversal steps are distinct from source faults and returns.

The two direct callers at `13A8:0A13` and `1CC2` execute ADD SP,6 and
ADD SP,8 immediately afterward, redefining arithmetic FLAGS. Parent
bodies, formatting context, output capacity, value/radix producers,
DS/SS lifetime, all writers and core integration remain open. No actual
DOS session, full resource decoding, renderer/audio output, complete
state-machine, gameplay or fidelity gate is established. CGA remains
behind EGA code-contract closure.
