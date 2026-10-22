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
// Decompiles functions with injected C struct types (cJSON) for high-fidelity source recovery
// @category AetherRE.TypeInjection

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

public class DecompileWithTypeInjection extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        File outDir;
        if (args.length > 0 && args[0] != null && !args[0].trim().isEmpty()) {
            outDir = new File(args[0].trim());
        } else {
            outDir = new File(System.getProperty("java.io.tmpdir"), "ghidra_typed_out");
        }
        if (!outDir.exists()) {
            outDir.mkdirs();
        }

        println("[AetherRE-TypeInjection] Target program: " + currentProgram.getName());
        println("[AetherRE-TypeInjection] Building cJSON struct definition in DataTypeManager...");

        DataTypeManager dtm = currentProgram.getDataTypeManager();
        int txId = currentProgram.startTransaction("Inject C Types");

        DataType resolvedCJson = null;
        try {
            // Build cJSON structure:
            // next (ptr), prev (ptr), child (ptr), type (int), valuestring (char*), valueint (int), valuedouble (double), string (char*)
            StructureDataType cjsonStruct = new StructureDataType("cJSON", 0);
            cjsonStruct.setPackingEnabled(true);

            PointerDataType ptrSelf = new PointerDataType(cjsonStruct);
            PointerDataType ptrChar = new PointerDataType(CharDataType.dataType);

            cjsonStruct.add(ptrSelf, 8, "next", "walk array/object chains");
            cjsonStruct.add(ptrSelf, 8, "prev", "walk array/object chains");
            cjsonStruct.add(ptrSelf, 8, "child", "child item");
            cjsonStruct.add(IntegerDataType.dataType, 4, "type", "item type bitmask");
            cjsonStruct.add(ptrChar, 8, "valuestring", "string value");
            cjsonStruct.add(IntegerDataType.dataType, 4, "valueint", "integer value");
            cjsonStruct.add(DoubleDataType.dataType, 8, "valuedouble", "floating point value");
            cjsonStruct.add(ptrChar, 8, "string", "name of item");

            resolvedCJson = dtm.addDataType(cjsonStruct, DataTypeConflictHandler.REPLACE_HANDLER);
            PointerDataType ptrCJson = new PointerDataType(resolvedCJson);

            println("[AetherRE-TypeInjection] Successfully registered cJSON struct (size: " + resolvedCJson.getLength() + " bytes).");

            // Apply to cJSON functions
            FunctionIterator funcIter = currentProgram.getFunctionManager().getFunctions(true);
            int typedFuncCount = 0;

            while (funcIter.hasNext()) {
                Function f = funcIter.next();
                String fname = f.getName();

                if (fname.startsWith("cJSON_") || fname.equals("cJSON_Delete")) {
                    boolean modified = false;

                    // Functions that return cJSON*
                    if (fname.contains("Create") || fname.contains("Parse") || fname.contains("Duplicate") || fname.contains("Detach") || fname.contains("GetArrayItem") || fname.contains("GetObjectItem")) {
                        try {
                            f.setReturnType(ptrCJson, SourceType.USER_DEFINED);
                            modified = true;
                        } catch (Exception ex) {
                            // ignore if incompatible
                        }
                    }

                    // Functions where first parameter is cJSON*
                    if (f.getParameterCount() > 0) {
                        try {
                            Parameter p0 = f.getParameter(0);
                            p0.setDataType(ptrCJson, SourceType.USER_DEFINED);
                            modified = true;
                        } catch (Exception ex) {
                            // ignore
                        }
                    }

                    // Functions where second parameter is cJSON* (e.g. AddItemToArray, AddItemToObject)
                    if (f.getParameterCount() > 1 && (fname.contains("AddItem") || fname.contains("ReplaceItem") || fname.contains("InsertItem"))) {
                        try {
                            Parameter p1 = f.getParameter(1);
                            p1.setDataType(ptrCJson, SourceType.USER_DEFINED);
                            modified = true;
                        } catch (Exception ex) {
                            // ignore
                        }
                    }

                    if (modified) {
                        typedFuncCount++;
                    }
                }
            }
            println("[AetherRE-TypeInjection] Injected types into " + typedFuncCount + " cJSON functions.");

        } finally {
            currentProgram.endTransaction(txId, true);
        }

        // Now run the decompiler
        DecompInterface decompiler = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        decompiler.setOptions(options);
        decompiler.openProgram(currentProgram);

        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
        File cOut = new File(outDir, "decompiled_typed.c");
        File summaryJson = new File(outDir, "typed_summary.json");

        PrintWriter cWriter = new PrintWriter(new FileWriter(cOut));
        PrintWriter jsonWriter = new PrintWriter(new FileWriter(summaryJson));

        jsonWriter.println("{");
        jsonWriter.println("  \"program\": \"" + currentProgram.getName() + "\",");
        jsonWriter.println("  \"functions\": [");

        boolean first = true;
        int decompCount = 0;
        FunctionIterator it2 = currentProgram.getFunctionManager().getFunctions(true);

        while (it2.hasNext()) {
            Function f = it2.next();
            String fname = f.getName();

            DecompileResults res = decompiler.decompileFunction(f, 30, monitor);
            if (res.decompileCompleted() && res.getDecompiledFunction() != null) {
                decompCount++;
                String cCode = res.getDecompiledFunction().getC();

                cWriter.println("// Function: " + fname + " @ " + f.getEntryPoint());
                cWriter.println(cCode);
                cWriter.println("\n");

                if (!first) jsonWriter.println(",");
                first = false;
                jsonWriter.print(String.format("    {\"name\": \"%s\", \"address\": \"%s\", \"success\": true, \"params\": %d, \"return_type\": \"%s\"}",
                        fname.replace("\"", "\\\""),
                        f.getEntryPoint(),
                        f.getParameterCount(),
                        f.getReturnType().getName().replace("\"", "\\\"")));
            }
        }

        jsonWriter.println();
        jsonWriter.println("  ],");
        jsonWriter.println("  \"total_decompiled\": " + decompCount);
        jsonWriter.println("}");

        cWriter.flush();
        cWriter.close();
        jsonWriter.flush();
        jsonWriter.close();
        decompiler.dispose();

        println("[AetherRE-TypeInjection] Complete! Decompiled " + decompCount + " functions with full struct recovery.");
        println("[AetherRE-TypeInjection] Output written to: " + cOut.getAbsolutePath());
    }
}
