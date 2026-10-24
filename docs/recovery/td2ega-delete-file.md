# DOS unlink wrapper and shared error tail

`FN-EGA-000341` (`13A8:2E20`) takes one SS near filename in current DS.
It saves BP, sets DX from the argument, and invokes INT21/AH41. The pinned
Microsoft DOS source identifies this service as UNLINK. All tests substitute
a synthetic service; no file deletion or actual DOS session occurs.

Success follows the shared0924 tail: AX0/CF0, MOVSP from returned BP,
POPBP and plain far return. DX retains the service response. Failure takes
the actual near CALL to094A with SS return093C and executes the reviewed
error mapper. If that return frame has changed, the raw coordinate is
exposed after near RET without following it. On normal child return,
AXFFFF/unprefixed99 sets DXFFFF while preserving mapper carry, then the
shared far-return tail uses returned BP and actual SS saved/root words.

The selected build-v2/comparison-v2 passed 6,144 cases, all 38 root/mapper
instruction sites and 83,808 original instruction events. Complete memory
including nested SS, GPR/BP/CF/IF/DF, service requests and control coordinates
are compared. Fixtures include 3,072 before-INT prefixes, 3,072 synthetic
services, 2,688 actual error-mapper calls, 2,848 root far returns, 224 raw
child near returns and 1,424 altered root-return coordinates. Returned DS,
BP, IF/DF and service writes to saved BP are explicit.

Native interface admission requires SP>=20, leaving the linked mapper's
minimum16-byte profile after BP save and near CALL. Build-v1 passed the
ordinary fixtures but exposed a looser guard during interface review; its
source, DLL, recipe and successful subset receipt remain preserved.
Build-v2 tightens that guard and repeats the complete comparison. Fourteen
native checks separately verify invalid profiles, minimum SP20 composition,
missing/bad adapter and before-INT budget outcomes.

Two direct caller candidates remain for review. Actual filename capacity,
other FLAGS use, writers/lifetime/exclusion and core integration are open.
Synthetic INT boundaries omit real interrupt frames and delivery. No actual
device, renderer, audio, complete state machine, gameplay or fidelity gate
is established. CGA remains behind EGA portable code-contract closure.
