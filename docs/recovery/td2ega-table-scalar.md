# Raw table and scalar selectors

Five functions now have instruction-derived C17 contracts. Their tables remain
external, with raw fields and units unassigned.

| Entry | Contract |
| --- | --- |
| 13A8:094A | Store incoming AL in DS6DA0; nonzero AH becomes signed AX directly, otherwise version-dependent byte remap/clamp then XLAT at DS6DDA; word sign extension and store DS6D95. Near return. |
| 13A8:2D57 | Search six descending CS bytes, 2CB3..2CAE. Match gives AX=4*index, BX=7058+AX, CF0; missing leaves AX unchanged, CX0/BX2CAD/CF1. BP save and far return. |
| 13A3:0012 | Sign-extend AL, take its absolute value, fold BL only when its **signed** value exceeds 5A, read DS54AA+2*index, and conditionally negate the word. AL80 retains index128. BX/DX saved in SS; far return. |
| 06C9:5334 | Signed BX ranges [-400,-1], [0,399], [400,800] select DS333E/3340/3342. Update only when signed AX is below that word; outside range skips update. Near return. |
| 06C9:535B | Signed field comparisons select CXFF38/C8/258; independent signed AX ranges select DX333E/100/3340/3342. Near return. |

The complete comparison passed 41,280 fixtures and all 105 instruction sites,
executing 686,488 original instructions. Complete bus, actual SS saves and
near/far frames, GPR/BP/CF/IF/DF and actual return coordinates are compared.
There are 672 overwritten return coordinates, exposed after the return
instruction without following arbitrary code. Nine native rejection checks
are separate. Both relocations, equal/unequal DS/SS, byte and signed-word
boundaries and external fixture tables are included.

Static review records 18 caller-owner records representing 12 unique direct
call sites. Shared 0939 code belongs to several graph owners; those records
are not distinct physical calls. Three embedded spans are identified from
consumer instructions: six CS selector bytes, twenty DS XLAT bytes, and 258
DS word-lookup bytes. The last overlaps the earlier DS5560 span at5560..55AB;
both consumer views remain recorded. No original table values are embedded
in C, and no full resource decoding is admitted.

Actual callers, other FLAGS use, table writers and lifetime, bounds/exclusion
and core integration remain open. No actual DOS session, device delivery,
renderer, audio output, complete state machine, gameplay or fidelity gate
is established. CGA remains behind EGA portable code-contract closure.
