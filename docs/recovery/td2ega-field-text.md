# Raw field text composition

`0432:0006` takes current-DS output and input offsets in two SS words. It
calls the actual2956 copy body with a real far frame and incoming DF. Its
own scalar loops then work forward, independent of that direction flag.

The first loop starts at offset17 and removes spaces downward while the
actual signed SS local remains positive. It never trims slot0, and checks
slot17 even if a NUL occurs earlier. The second loop resets the actual SS
local to0, rereads the output argument and local each time, stops at NUL,
and replaces spaces with underscores. The original has no capacity check.
An18-space input consequently leaves an underscore in slot0 and zeroes
slots1..18. Short inputs retain trailing spaces when slot17 is not a space.

The C17 `/W4 /WX` build passed11,216 comparisons,1,242,306 original
instructions and all60 root/child sites. Full bus/SS, GPR/BP/CF/IF/DF,
control and write counts match. Coverage includes6,608 actual far calls,
5,608 DS=SS cases,5,608 reverse-DF cases,3,072 minimum-SP30 cases,
472 changed child returns and220 changed root returns. Fifteen native
diagnostics are separate. Call, child-operation and parent-loop budgets
retain different before-instruction boundaries.

Actual child-returned BP and parent SS locals, arguments, saved SI/BP and
far-return words remain live bus reads. Raw changed return targets are
exposed after RET and never followed. Four direct caller windows are
recorded; whole callers, NUL/capacity/DF validity, writers, ownership,
lifetime, interrupt exclusion and core integration remain open.

No complete text/resource schema, DOS session, renderer, audio output,
complete state-machine, gameplay or fidelity acceptance is established.
