// Decompile functions: "<addr>" = all referencing <addr>, "callers:<addr>" = all calling the function at <addr>, "fn:<addr>" = that function.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.util.*;

public class DecompRefs extends GhidraScript {
    @Override
    public void run() throws Exception {
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        Set<Function> fns = new LinkedHashSet<>();
        for (String a : getScriptArgs()) {
            if (a.startsWith("callers:")) {
                Function t = getFunctionAt(toAddr(Long.parseLong(a.substring(8), 16)));
                for (Reference r : getReferencesTo(t.getEntryPoint())) {
                    Function f = getFunctionContaining(r.getFromAddress());
                    if (f != null) fns.add(f);
                }
                continue;
            }
            if (a.startsWith("fn:")) {
                Function f = getFunctionContaining(toAddr(Long.parseLong(a.substring(3), 16)));
                if (f != null) fns.add(f); else println("no function at " + a);
                continue;
            }
            Address addr = toAddr(Long.parseLong(a, 16));
            for (Reference r : getReferencesTo(addr)) {
                Function f = getFunctionContaining(r.getFromAddress());
                println("ref " + addr + " <- " + r.getFromAddress() + " in " + (f == null ? "?" : f.getName() + "@" + f.getEntryPoint()));
                if (f != null) fns.add(f);
            }
        }
        for (Function f : fns) {
            DecompileResults res = di.decompileFunction(f, 60, monitor);
            println("===== " + f.getName() + " @ " + f.getEntryPoint());
            println(res.decompileCompleted() ? res.getDecompiledFunction().getC() : "decompile failed: " + res.getErrorMessage());
        }
    }
}
