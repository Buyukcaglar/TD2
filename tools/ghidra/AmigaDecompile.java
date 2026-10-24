// Post-analysis script: decompiles every function into one C file, each headed by its address.
// Argument: the output file.
// @category TD2

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import java.io.PrintWriter;

public class AmigaDecompile extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        int n = 0;
        try (PrintWriter out = new PrintWriter(getScriptArgs()[0], "UTF-8")) {
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                DecompileResults r = dec.decompileFunction(f, 60, monitor);
                out.println("/* ==== " + f.getEntryPoint() + " " + f.getName() + " ==== */");
                out.println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "/* failed: " + r.getErrorMessage() + " */");
                n++;
            }
        }
        println(n + " functions decompiled");
    }
}
