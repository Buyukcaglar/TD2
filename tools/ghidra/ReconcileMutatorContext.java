// Context only: do not patch canonical program bytes to a runtime code state.
// @category TestDrive2.Recovery
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;

public class ReconcileMutatorContext extends GhidraScript {
    private Address at(int offset) {
        return currentProgram.getAddressFactory().getAddress(String.format("23a8:%04x", offset));
    }
    private String value(Register register, Address address) {
        BigInteger v = currentProgram.getProgramContext().getValue(register,address,false);
        return v == null ? "unknown" : v.toString(16);
    }
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        Path output = Path.of(args[0]).toAbsolutePath().normalize();
        boolean verifyOnly = args.length > 1 && args[1].equals("readback");
        if (!output.startsWith(Path.of("C:/Projects/TestDrive2/docs/recovery/evidence")) || Files.exists(output))
            throw new IllegalArgumentException("Fresh metadata evidence required");
        if (!currentProgram.getExecutableSHA256().equals("71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2"))
            throw new IllegalArgumentException("Unadmitted MZ");
        byte[] before = new byte[130240];
        Address base = currentProgram.getAddressFactory().getAddress("1000:0000");
        if (currentProgram.getMemory().getBytes(base,before) != before.length)
            throw new IllegalStateException("Image read incomplete");
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(before));
        if (!hash.equals("e36b827719c4692f9f89c5ba5d647111a82e61e8843f4d8b32ee653b7280ba99"))
            throw new IllegalStateException("Canonical relocated bytes changed");
        // Values apply before each instruction. Entry DS and restored caller DS
        // remain symbolic; SS is inherited and no SS assignment occurs here.
        int[][] ranges = {
            {0x003b,0x0045,0},
            {0x0046,0x0163,0x23a8},
            {0x0169,0x0180,0x16c9},
            {0x0182,0x0187,0x2793},
            {0x0189,0x01a2,0x23a8},
            {0x01a3,0x01a7,0}
        };
        Register ds = currentProgram.getRegister("DS");
        JsonArray rows = new JsonArray();
        for (int[] range : ranges) {
            Address first = at(range[0]), last = at(range[1]);
            JsonObject row = new JsonObject();
            row.addProperty("start",first.toString()); row.addProperty("end_inclusive",last.toString());
            row.addProperty("register","DS"); row.addProperty("before_start",value(ds,first));
            row.addProperty("before_end",value(ds,last));
            if (!verifyOnly) currentProgram.getProgramContext().setValue(ds,first,last,BigInteger.valueOf(range[2]));
            row.addProperty("after_start",value(ds,first)); row.addProperty("after_end",value(ds,last));
            if (!value(ds,first).equals(Integer.toHexString(range[2])) || !value(ds,last).equals(Integer.toHexString(range[2])))
                throw new IllegalStateException("Mutator DS context readback failed");
            rows.add(row);
        }
        byte[] after = new byte[before.length]; currentProgram.getMemory().getBytes(base,after);
        if (!java.util.Arrays.equals(before,after)) throw new IllegalStateException("Context edit changed bytes");
        JsonObject result = new JsonObject();
        result.addProperty("result","pass"); result.addProperty("mode",verifyOnly ? "saved_readback" : "context_only_edit");
        result.addProperty("image_bytes_unchanged",true); result.addProperty("relocated_image_sha256",hash);
        result.addProperty("load_segment",0x1000); result.add("fixed_context_ranges",rows);
        result.addProperty("entry_DS",value(ds,at(0x2e))); result.addProperty("restored_caller_DS",value(ds,at(0x1a8)));
        result.addProperty("limits","Six instruction-established DS ranges in main-called mutator/helper context. SS inherited; entry/restored DS symbolic. Canonical program bytes remain initial image, so prepared opcode boundaries require separate mutable-state ledgers. No decompiler prototype or runtime profile admitted.");
        Files.writeString(output,new GsonBuilder().setPrettyPrinting().create().toJson(result)+"\n");
        println("Verified six mutator DS ranges; canonical bytes unchanged; mode="+(verifyOnly ? "readback" : "edit"));
    }
}
