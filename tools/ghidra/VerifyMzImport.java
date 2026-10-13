// Independently check every imported byte and relocation against admitted input.
// @category TestDrive2.Recovery
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

public class VerifyMzImport extends GhidraScript {
    private int u16(byte[] data, int offset) {
        return (data[offset] & 255) | ((data[offset + 1] & 255) << 8);
    }
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) throw new IllegalArgumentException("raw-image normalized-MZ output-record required");
        byte[] raw = Files.readAllBytes(Path.of(args[0]));
        byte[] mz = Files.readAllBytes(Path.of(args[1]));
        Path output = Path.of(args[2]).toAbsolutePath().normalize();
        if (!output.startsWith(Path.of("C:/Projects/TestDrive2/docs/recovery/evidence")))
            throw new IllegalArgumentException("Metadata output outside recovery evidence");
        if (Files.exists(output)) throw new IllegalArgumentException("Record already exists");
        byte[] expected = raw.clone(); int count = u16(mz, 6); int table = u16(mz, 24);
        for (int i = 0; i < count; i++) {
            int relative = u16(mz, table + i * 4) + u16(mz, table + i * 4 + 2) * 16;
            int fixed = (u16(expected, relative) + 0x1000) & 65535;
            expected[relative] = (byte)fixed; expected[relative + 1] = (byte)(fixed >> 8);
        }
        byte[] actual = new byte[raw.length];
        Address base = currentProgram.getAddressFactory().getAddress("1000:0000");
        int read = currentProgram.getMemory().getBytes(base, actual);
        int mismatches = 0;
        for (int i = 0; i < expected.length; i++) if (expected[i] != actual[i]) mismatches++;
        JsonObject record = new JsonObject();
        record.addProperty("method", "Read saved Ghidra program; independent whole-image relocation calculation");
        record.addProperty("image_bytes_checked", read); record.addProperty("relocations_checked", count);
        record.addProperty("mismatched_bytes", mismatches);
        record.addProperty("load_segment", 0x1000); record.addProperty("program", currentProgram.getName());
        record.addProperty("imported_mz_sha256", currentProgram.getExecutableSHA256());
        record.addProperty("relocated_image_sha256", HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(actual)));
        JsonArray contexts = new JsonArray();
        for (String location : new String[]{"23a8:03f8", "23a8:0471", "1000:07b3"}) {
            Address address = currentProgram.getAddressFactory().getAddress(location); JsonObject row = new JsonObject();
            row.addProperty("address", location);
            for (String name : new String[]{"CS", "DS", "SS", "ES"}) {
                Register register = currentProgram.getRegister(name);
                var value = currentProgram.getProgramContext().getValue(register, address, false);
                row.addProperty(name, value == null ? "unknown" : value.toString(16));
            }
            contexts.add(row);
        }
        record.add("tool_register_contexts", contexts);
        record.addProperty("register_context_limit", "Unknown/wrong tool DS or SS is not evidence against instruction-derived startup values. Do not admit decompiler prototypes until manually reconciled.");
        record.addProperty("result", mismatches == 0 && read == raw.length ? "pass" : "fail");
        Files.writeString(output, new GsonBuilder().setPrettyPrinting().create().toJson(record) + "\n", StandardCharsets.UTF_8);
        println("Verified " + read + " bytes, " + count + " relocations, mismatches=" + mismatches);
        if (mismatches != 0 || read != raw.length) throw new IllegalStateException("Import differs from admitted image");
    }
}
