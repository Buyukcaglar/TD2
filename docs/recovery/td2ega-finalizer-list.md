# Reverse runtime callback list

`FN-EGA-000263` (`13A8:060D`) is a near helper. It compares SI and DI
unsigned, subtracts four from DI while SI<DI, skips a zero word pair,
and far-calls `[DS:DI]`. The actual far frame contains CS and061D.
Returned callback registers, DS and list position feed the next iteration.
The root ends with near RET2.

The zero test reads two separately computed word effective addresses. The
indirect far CALL reads one four-byte memory operand. Sixty-four boundary
fixtures distinguish those views at DI=FFFE. Another 448 fixtures place
the operand at the future child frame, including 224 DS=SS aliases, and
confirm operand capture before the CALL overwrites that location.

The build-v1/comparison-v2 passed 6,656 cases and all nine instruction sites,
with 60,528 original instruction events. Complete memory including nested
SS frames, GPR/BP/CF/IF/DF, requests and control coordinates are compared.
There are 3,984 root near returns, 2,384 before-record prefixes and 288
raw child far returns. The 3,424 synthetic callback RETF instructions are
counted separately from original instructions. Fourteen native profile,
budget, minimum-SP and adapter checks are separate.

Static review distinguishes twenty graph-owner records from six actual
direct call sites. The fixed bounds at0575/057E are empty7082 spans;
058B is empty841A; 0594 uses7082..7086; 05A2/05AB are empty7086.
Thus direct0599 has empty spans; the nonempty span belongs to0582's path.
Its initialized target is relocated13A8:0A3A. That target body, actual DS
view, all writers/aliases and callback lifetime remain open. The061B
indirect entry remains `complete=false` in the selected review.

Synthetic callbacks exercise returned DS, list bounds, GPR/BP/IF/DF,
zeroing the next entry and mutations of root or child return frames.
They establish the service ABI and walker, not original callback bodies
or supported arbitrary targets. Actual caller capacity, other FLAGS use,
writer ownership, exclusion and core integration remain open. No DOS
session, device/IRQ delivery, renderer, audio, complete state machine,
gameplay or fidelity acceptance is established. CGA remains behind EGA
portable code-contract closure.
