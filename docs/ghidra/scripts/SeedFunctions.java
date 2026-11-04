// Disassemble and create functions at the given hex addresses (Thumb), then let auto-analysis follow calls.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.program.model.address.Address;

public class SeedFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        for (String a : getScriptArgs()) {
            Address addr = toAddr(Long.parseLong(a, 16));
            if (currentProgram.getMemory().contains(addr)) {
                new ArmDisassembleCommand(addr, null, true).applyTo(currentProgram, monitor);
                if (getFunctionAt(addr) == null) createFunction(addr, null);
            }
        }
        analyzeAll(currentProgram);
        println("functions: " + currentProgram.getFunctionManager().getFunctionCount());
    }
}
