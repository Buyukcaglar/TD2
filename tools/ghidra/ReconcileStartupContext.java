// Apply only instruction-reviewed, fixed DS/SS ranges in a NEW project.
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

public class ReconcileStartupContext extends GhidraScript {
    private Address at(int segment, int offset) {
        return currentProgram.getAddressFactory().getAddress(String.format("%04x:%04x", segment + 0x1000, offset));
    }
    private String value(Register reg, Address address) {
        BigInteger v = currentProgram.getProgramContext().getValue(reg, address, false);
        return v == null ? "unknown" : v.toString(16);
    }
    @Override public void run() throws Exception {
        Path output = Path.of(getScriptArgs()[0]).toAbsolutePath().normalize();
        if (!output.startsWith(Path.of("C:/Projects/TestDrive2/docs/recovery/evidence")) || Files.exists(output))
            throw new IllegalArgumentException("Fresh recovery evidence path required");
        if (!currentProgram.getExecutableSHA256().equals("71b5a2113033dd456b049b75f26f1996284a3ffb75d082c350003caa8b0289a2"))
            throw new IllegalArgumentException("Unadmitted MZ");
        byte[] before = new byte[130240];
        if (currentProgram.getMemory().getBytes(at(0, 0), before) != before.length) throw new IllegalStateException("Image read incomplete");
        String imageHash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(before));
        if (!imageHash.equals("e36b827719c4692f9f89c5ba5d647111a82e61e8843f4d8b32ee653b7280ba99"))
            throw new IllegalStateException("Relocated image mismatch");
        // Inclusive instruction-byte ranges; values apply BEFORE each instruction.
        int[][] ranges = {
            {0x13a8,0x0417,0x088b,0x278f,1},
            {0x13a8,0x0420,0x0431,0x278f,0},
            {0x13a8,0x0471,0x0494,0x278f,0},
            {0x13a8,0x04a0,0x04d3,0x278f,0},
            {0x13a8,0x04d4,0x04dd,0x23a8,0},
            {0x13a8,0x04de,0x04f0,0x278f,0},
            {0x13a8,0x04fe,0x0505,0x278f,0},
            {0x13a8,0x0512,0x053f,0x278f,0},
            {0x13a8,0x0553,0x05ee,0x278f,0},
            {0x13a8,0x05f8,0x0602,0x278f,0},
            {0x13a8,0x060d,0x06d7,0x278f,0},
            {0x13a8,0x0756,0x0779,0x278f,0},
            {0x13a8,0x081e,0x082d,0x278f,0},
            {0x13a8,0x0854,0x0869,0x278f,0},
            {0x13a8,0x0887,0x088b,0x278f,0},
            {0x0000,0x07b3,0x07c7,0x278f,0},
            {0x0000,0x07b3,0x0c03,0x278f,1}
        };
        JsonArray rows = new JsonArray();
        for (int[] r : ranges) {
            Register reg = currentProgram.getRegister(r[4] == 0 ? "DS" : "SS");
            Address start = at(r[0],r[1]), end = at(r[0],r[2]);
            JsonObject row = new JsonObject();
            row.addProperty("start", start.toString()); row.addProperty("end_inclusive", end.toString());
            row.addProperty("register", reg.getName()); row.addProperty("before_start", value(reg,start));
            row.addProperty("before_end", value(reg,end));
            currentProgram.getProgramContext().setValue(reg, start, end, BigInteger.valueOf(r[3]));
            row.addProperty("after_start", value(reg,start)); row.addProperty("after_end", value(reg,end));
            if (!value(reg,start).equals(Integer.toHexString(r[3])) || !value(reg,end).equals(Integer.toHexString(r[3])))
                throw new IllegalStateException("Context readback failure");
            rows.add(row);
        }
        byte[] after = new byte[before.length]; currentProgram.getMemory().getBytes(at(0,0), after);
        if (!java.util.Arrays.equals(before, after)) throw new IllegalStateException("Context edit changed image bytes");
        JsonObject result = new JsonObject();
        result.addProperty("result","pass"); result.addProperty("program",currentProgram.getName());
        result.addProperty("load_segment",0x1000); result.addProperty("relocated_image_sha256",imageHash);
        result.addProperty("image_bytes_unchanged",true); result.add("fixed_context_ranges",rows);
        result.addProperty("limits","PSP/environment/LDS-selected DS stays symbolic; main DS after first call is not globally forced. Fixed ranges are reviewed startup-path assumptions, not runtime observations. No prototypes inferred.");
        Files.writeString(output,new GsonBuilder().setPrettyPrinting().create().toJson(result)+"\n");
        println("Applied and read back " + ranges.length + " bounded register contexts without byte edits");
    }
}
