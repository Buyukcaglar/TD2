# Record name selection

`0000:0730` now composes actual2B40 and2956 string helpers in C. It
initializes a current-DS index toFFFF and an SS local counter to0, rereads
the signed count90AA on each iteration, and compares the query9212 against
records at865C with a32-byte stride. Every matching record updates the
index, so the last match wins. Names, counts and indices retain raw word
wrap and the helpers' incoming DF behavior.

If the selected index is negative, the body copies the first record name
to the query and sets index0. It then copies the selected name again.
Zero or negative counts still take that fallback; they do not produce a
host-level empty-table error. The record-name case is copied from the
source record after the case-insensitive comparison.

The last far copy at079B leaves both arguments on the stack. The body
rereads the current index, shifts it left five bits, reads the record word
at+26 and stores it at8A80. MOV SP,actual BP then discards those arguments
and the local before POP BP/RETF. One caller supplies the far frame with
PUSH CS plus a near CALL; the other uses an explicit far CALL. Both next
enter0645:0000, whose initial SUB SP replaces arithmetic flags before use.

All six principal-coordinate data views are beyond the initialized image
in BSS. They are runtime candidates, not embedded-resource span identities
or decoded schemas. Under DS=SS, a child's saved BP can overwrite the index
at8CFA; the final shift then retains the changed index and its carry.
The fixed query destination can also overwrite a child's far-return CS.
Changed targets are exposed after RET and never followed.

The C17 `/W4 /WX` build passed8,160 comparisons,975,022 original
instructions and all106 feasible sites in the108-site family fence. The
two excluded2956 odd-destination instructions are infeasible only because
this parent's last argument push fixes destination9212; standalone2956
covers its complete body. Full bus/SS, registers/BP/CF/IF/DF, control and
budgets match. Coverage includes20,070 far calls, six changed child returns,
104 changed root returns and104 carry-set index-alias cases. Twenty-three
native checks are separate. Earlier8,144 cases passed; the selected run
adds explicit child-return aliases with C and DLL unchanged.

Complete callers, all BSS writers, valid counts, names, NUL bounds, index
domains, DF assumptions, capacities, ownership, lifetime, interrupt exclusion
and core integration remain open. Historical CPU/A20 behavior remains
unqualified. No DOS session, renderer, audio, complete state-machine,
gameplay or fidelity acceptance is established. CGA remains behind EGA
portable code-contract closure.
