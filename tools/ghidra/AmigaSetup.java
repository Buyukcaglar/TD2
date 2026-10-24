// Pre-analysis script for an Amiga load file laid out by tools/amiga/hunk.py (raw image from address 0).
// Arguments: A4 value, code start, code end, data end (hex). Sets A4 for the whole code range (Lattice
// small data), marks a function at every "link a5" (4E55) so analysis finds the C functions, and marks
// the jump stubs in the data that A4-relative calls go through.
// @category TD2

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ProgramContext;
import java.math.BigInteger;

public class AmigaSetup extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        long a4 = Long.parseLong(a[0], 16), start = Long.parseLong(a[1], 16), end = Long.parseLong(a[2], 16);
        Address s = toAddr(start), e = toAddr(end - 1);
        Register reg = currentProgram.getRegister("A4");
        ProgramContext ctx = currentProgram.getProgramContext();
        ctx.setValue(reg, s, e, BigInteger.valueOf(a4));
        int n = 0;
        for (long p = start; p + 2 <= end; p += 2) {
            Address at = toAddr(p);
            if ((getShort(at) & 0xFFFF) == 0x4E55) {
                addEntryPoint(at);
                disassemble(at);
                createFunction(at, null);
                n++;
            }
        }
        // The linker's far-call stubs (jmp abs.l) that "jsr d16(a4)" reaches, in the data after the code.
        int stubs = 0;
        long dataEnd = a.length > 3 ? Long.parseLong(a[3], 16) : end;
        for (long p = end & ~1L; p + 6 <= dataEnd; p += 2) {
            Address at = toAddr(p);
            if ((getShort(at) & 0xFFFF) == 0x4EF9) {
                long target = getInt(toAddr(p + 2)) & 0xFFFFFFFFL;
                if (target >= start && target < end) {
                    disassemble(at);
                    createFunction(at, null);
                    stubs++;
                }
            }
        }
        addEntryPoint(s);
        disassemble(s);
        println("A4 set, " + n + " link frames and " + stubs + " jump stubs marked");
    }
}
