// Export analysis metadata and private decompiler hypotheses. No original edits.
// @category TestDrive2.Recovery
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.mem.MemoryBlock;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;

public class ExportRecovery extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) throw new IllegalArgumentException("Private output directory required");
        Path out = Path.of(args[0]).toAbsolutePath().normalize();
        Path privateRoot = Path.of("C:/Projects/TestDrive2/analysis").toAbsolutePath().normalize();
        if (!out.startsWith(privateRoot)) throw new IllegalArgumentException("Output must be private analysis");
        if (Files.exists(out)) throw new IllegalArgumentException("Refusing existing export directory");
        Files.createDirectories(out);
        JsonObject result = new JsonObject();
        result.addProperty("program", currentProgram.getName());
        result.addProperty("language", currentProgram.getLanguageID().toString());
        result.addProperty("compiler_spec", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        result.addProperty("address_space", currentProgram.getAddressFactory().getDefaultAddressSpace().getClass().getName());
        result.addProperty("image_base", currentProgram.getImageBase().toString());
        result.addProperty("executable_format", currentProgram.getExecutableFormat());
        result.addProperty("executable_sha256", currentProgram.getExecutableSHA256());
        result.addProperty("instruction_count", currentProgram.getListing().getNumInstructions());
        result.addProperty("data_count", currentProgram.getListing().getNumDefinedData());
        JsonArray entries = new JsonArray();
        var entryIt = currentProgram.getSymbolTable().getExternalEntryPointIterator();
        while (entryIt.hasNext()) entries.add(entryIt.next().toString());
        result.add("external_entries", entries);
        JsonArray blocks = new JsonArray();
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            JsonObject row = new JsonObject();
            row.addProperty("name", block.getName()); row.addProperty("start", block.getStart().toString());
            row.addProperty("end", block.getEnd().toString()); row.addProperty("bytes", block.getSize());
            row.addProperty("initialized", block.isInitialized()); row.addProperty("execute", block.isExecute());
            row.addProperty("write", block.isWrite()); blocks.add(row);
        }
        result.add("blocks", blocks);
        JsonArray functions = new JsonArray();
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        Path pseudo = out.resolve("decompiler-hypotheses");
        Files.createDirectories(pseudo);
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        int count = 0;
        while (it.hasNext() && !monitor.isCancelled()) {
            Function function = it.next(); JsonObject row = new JsonObject();
            Address entry = function.getEntryPoint();
            row.addProperty("name", function.getName()); row.addProperty("entry", entry.toString());
            row.addProperty("entry_flat", entry.getOffset()); row.addProperty("body_bytes", function.getBody().getNumAddresses());
            row.addProperty("calling_convention", function.getCallingConventionName());
            row.addProperty("signature", function.getSignature().toString());
            JsonArray callers = new JsonArray();
            for (Function caller : function.getCallingFunctions(monitor)) callers.add(caller.getEntryPoint().toString());
            row.add("callers", callers);
            JsonArray callees = new JsonArray();
            for (Function callee : function.getCalledFunctions(monitor)) callees.add(callee.getEntryPoint().toString());
            row.add("callees", callees);
            DecompileResults decoded = decompiler.decompileFunction(function, 15, monitor);
            row.addProperty("decompile_completed", decoded.decompileCompleted());
            if (decoded.decompileCompleted() && decoded.getDecompiledFunction() != null) {
                String filename = entry.toString().replace(':', '_') + ".c";
                Files.writeString(pseudo.resolve(filename), decoded.getDecompiledFunction().getC(), StandardCharsets.UTF_8);
                row.addProperty("private_pseudocode", "decompiler-hypotheses/" + filename);
            } else row.addProperty("decompile_error", decoded.getErrorMessage());
            functions.add(row); count++;
        }
        decompiler.dispose(); result.add("functions", functions); result.addProperty("function_count", count);
        result.addProperty("status", "Automatic analysis hypotheses, not reviewed portable C or reachable-code coverage");
        Files.writeString(out.resolve("program-analysis.json"), new GsonBuilder().setPrettyPrinting().create().toJson(result) + "\n", StandardCharsets.UTF_8);
        StringBuilder listing = new StringBuilder();
        InstructionIterator instructions = currentProgram.getListing().getInstructions(true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            listing.append(instruction.getAddress()).append("  ").append(instruction).append('\n');
        }
        Files.writeString(out.resolve("instructions.txt"), listing, StandardCharsets.UTF_8);
        println("Exported " + count + " candidate functions to " + out);
    }
}
