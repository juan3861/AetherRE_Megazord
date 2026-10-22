/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Decompile all functions in the current program and export C source + High P-Code
// @category AetherRE.Decompiler

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.Iterator;

public class DecompileAllFunctions extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        File outDir;
        if (args.length > 0 && args[0] != null && !args[0].trim().isEmpty()) {
            outDir = new File(args[0].trim());
        } else {
            outDir = new File(System.getProperty("java.io.tmpdir"), "ghidra_decomp_out");
        }
        if (!outDir.exists()) {
            outDir.mkdirs();
        }

        println("[AetherRE-Ghidra] Output directory: " + outDir.getAbsolutePath());
        println("[AetherRE-Ghidra] Analyzing program: " + currentProgram.getName());

        DecompInterface decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decompiler.setOptions(options);
        
        boolean opened = decompiler.openProgram(currentProgram);
        if (!opened) {
            printerr("[AetherRE-Ghidra] Failed to initialize Ghidra decompiler interface!");
            return;
        }

        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
        FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);

        File combinedCFile = new File(outDir, "decompiled_all.c");
        File summaryJsonFile = new File(outDir, "decompilation_summary.json");
        File pcodeFile = new File(outDir, "high_pcode.txt");

        PrintWriter cWriter = new PrintWriter(new FileWriter(combinedCFile));
        PrintWriter pcodeWriter = new PrintWriter(new FileWriter(pcodeFile));
        PrintWriter jsonWriter = new PrintWriter(new FileWriter(summaryJsonFile));

        cWriter.println("// ==========================================================================");
        cWriter.println("// Decompiled by AetherRE Ghidra Headless Bridge");
        cWriter.println("// Program: " + currentProgram.getName());
        cWriter.println("// Executable Path: " + currentProgram.getExecutablePath());
        cWriter.println("// Creation Date: " + currentProgram.getCreationDate());
        cWriter.println("// ==========================================================================\n");

        jsonWriter.println("{");
        jsonWriter.println("  \"program\": \"" + currentProgram.getName().replace("\\", "\\\\") + "\",");
        jsonWriter.println("  \"functions\": [");

        int count = 0;
        int decompiledCount = 0;
        boolean firstJson = true;

        while (funcIter.hasNext() && !monitor.isCancelled()) {
            Function func = funcIter.next();
            count++;

            String funcName = func.getName();
            String entryAddr = func.getEntryPoint().toString();
            int paramCount = func.getParameterCount();
            String retType = func.getReturnType().getName();

            DecompileResults results = decompiler.decompileFunction(func, 30, monitor);
            boolean success = results.decompileCompleted();

            if (!firstJson) {
                jsonWriter.println(",");
            }
            firstJson = false;

            jsonWriter.print(String.format("    {\"name\": \"%s\", \"address\": \"%s\", \"success\": %b, \"params\": %d, \"return_type\": \"%s\"}",
                    funcName.replace("\"", "\\\""),
                    entryAddr,
                    success,
                    paramCount,
                    retType.replace("\"", "\\\"")));

            if (success && results.getDecompiledFunction() != null) {
                decompiledCount++;
                String cSource = results.getDecompiledFunction().getC();
                cWriter.println("// Function: " + funcName + " @ " + entryAddr);
                cWriter.println(cSource);
                cWriter.println("\n");

                HighFunction highFunc = results.getHighFunction();
                if (highFunc != null) {
                    pcodeWriter.println("### Function: " + funcName + " @ " + entryAddr);
                    Iterator<PcodeOpAST> opIter = highFunc.getPcodeOps();
                    while (opIter.hasNext()) {
                        PcodeOpAST op = opIter.next();
                        pcodeWriter.println("  " + op.toString());
                    }
                    pcodeWriter.println();
                }
            } else {
                cWriter.println("// Function: " + funcName + " @ " + entryAddr + " [FAILED TO DECOMPILE]");
                cWriter.println("// Error: " + results.getErrorMessage() + "\n");
            }
        }

        jsonWriter.println();
        jsonWriter.println("  ],");
        jsonWriter.println("  \"total_functions\": " + count + ",");
        jsonWriter.println("  \"decompiled_functions\": " + decompiledCount);
        jsonWriter.println("}");

        cWriter.flush();
        cWriter.close();
        pcodeWriter.flush();
        pcodeWriter.close();
        jsonWriter.flush();
        jsonWriter.close();

        decompiler.dispose();

        println(String.format("[AetherRE-Ghidra] Completed! Total functions: %d, Successfully decompiled: %d", count, decompiledCount));
        println("[AetherRE-Ghidra] C Source exported to: " + combinedCFile.getAbsolutePath());
        println("[AetherRE-Ghidra] Summary JSON exported to: " + summaryJsonFile.getAbsolutePath());
        println("[AetherRE-Ghidra] High P-Code exported to: " + pcodeFile.getAbsolutePath());
    }
}
