# Indexed width lookup and a state write after the child returns

`FN-EGA-000385`, `06C9:4C85`, masks a byte selector to127 and reads a
token from current DS. Negative tokens return. Tokens below80 test one
of80 strided words and can select an inline byte width. The alternate
path loads ES from940E and reads a near offset and width within that ES.
It retains the original segment and near-pointer distinctions.

The external lookup divides token-minus30 by5 using byte DIV. AL holds
the quotient and AH the remainder; the following word shift includes
both. The address is `2*quotient + 512*remainder`, with98 possible word
offsets0..2084. This matches the byte form in the
[Intel instruction reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2a-manual.pdf#page=388).
The literal input range0..97 and divisor5 exclude division faults on this
path. Required flags are defined by later instructions.

A signed byte coefficient times50, adjusted by500 and sometimes400,
feeds actual `4D26`. A successful guard makes a near CALL to `4A2E`.
Unsigned BP>=20 chooses the path that writes state2 after the child
returns. This decision precedes the child and survives later BP changes.
Two sets of96 comparisons verify crossings of that BP threshold through
actual stack aliases. A changed child return address stops before the
state write; original child effects remain visible.

[85,440 comparisons](evidence/td2ega-indexed-sample-validation-v2.json)
passed7,104,452 original instructions and all196 root/guard/child sites
at two load addresses. Whole RAM, registers/BP, CF/IF/DF, root ZF, CALL
counts and actual near/far returns match compiled C17. They include all128
masked selectors, all98 byte-DIV inputs and all256 coefficient bytes.
[447 native checks](evidence/td2ega-indexed-sample-native-diagnostics-v2.json)
and [static review](evidence/td2ega-indexed-sample-context-v1.json)
are separate. The earlier81,792 matching comparisons lacked five inherited
control/threshold sites. Added fixtures close that coverage gap. A native
poison object was moved after it overlapped a valid lookup slot; the exact
failed scripts/logs are retained. C and DLL are unchanged.

RS284/285 identify two initialized128-byte zero views at368A and370A,
inside the known7774-byte DAT-copy range. RS286 identifies the318-byte
footprint at1DB4:80 tested word slots and158 unread interleaved bytes.
These are program-data identities and code index bounds, with no complete
resource format or writable-capacity acceptance. No original table payload
is embedded in C and no supplied resource is decoded by this packet.

Actual caller DS/SS/SP and BP, all writers, object capacities, field units,
storage lifetime, shared-source reset/seed, IRQ exclusion and core integration
remain open. No DOS game session, renderer, audio output, complete state
machine, gameplay or fidelity acceptance is established. Physical086C remains
unassigned. CGA follows EGA portable code-contract closure; full resource
decoding, Windows gameplay and Amiga recovery have not started.
