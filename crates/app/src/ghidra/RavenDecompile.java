// Export C pseudocode for a function identified by its original file offset.
//@category RAVEN
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.Set;

public class RavenDecompile extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        long offset = Long.parseLong(args[0]);
        Set<Function> matches = new LinkedHashSet<>();
        for (Address address : currentProgram.getMemory().locateAddressesForFileOffset(offset)) {
            Function function = getFunctionAt(address);
            if (function != null) {
                matches.add(function);
            }
        }
        if (matches.size() != 1) {
            throw new IOException("Expected one function entry at file offset " + offset +
                ", found " + matches.size());
        }
        Function function = matches.iterator().next();
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) {
                throw new IOException(decompiler.getLastMessage());
            }
            DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
            if (!result.decompileCompleted() || result.getDecompiledFunction() == null) {
                throw new IOException("Ghidra decompilation failed: " + result.getErrorMessage());
            }
            Files.writeString(Path.of(args[2]), function.getEntryPoint().toString());
            Files.writeString(Path.of(args[1]), result.getDecompiledFunction().getC());
        } finally {
            decompiler.dispose();
        }
    }
}
