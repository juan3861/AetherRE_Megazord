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
// Static export of observed Ghidra program types; no type hypotheses injected.
// @category AetherRE.Decompiler
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.address.AddressSpace;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.HashMap;
import java.util.Map;
import java.security.MessageDigest;

public class DecompileAllFunctions extends GhidraScript {
    private JsonObject observedIndirectEffects(HighFunction high, Function function, String hash,
                                              JsonObject structured, byte[] irBytes) throws Exception {
        Map<SequenceNumber,String> identities = new HashMap<>();
        ArrayList<PcodeOp> inventory = new ArrayList<>();
        JsonArray exported = structured.getAsJsonArray("operations");
        for (PcodeBlockBasic block : high.getBasicBlocks()) {
            Iterator<PcodeOp> iterator = block.getIterator();
            while (iterator.hasNext()) {
                PcodeOp operation = iterator.next();
                int index = inventory.size();
                if (index >= exported.size()) throw new IllegalArgumentException("indirect_effect_inventory_changed");
                JsonObject row = exported.get(index).getAsJsonObject();
                JsonObject sequence = row.getAsJsonObject("sequence");
                String identity = "o" + index;
                if (!identity.equals(row.get("id").getAsString()) ||
                    !operation.getSeqnum().getTarget().toString(true).equals(sequence.get("pc").getAsString()) ||
                    Integer.toUnsignedLong(operation.getSeqnum().getTime()) != sequence.get("time").getAsLong() ||
                    identities.put(operation.getSeqnum(),identity) != null)
                    throw new IllegalArgumentException("indirect_effect_inventory_changed");
                inventory.add(operation);
            }
        }
        if (inventory.size()!=exported.size()) throw new IllegalArgumentException("indirect_effect_inventory_changed");
        JsonArray entries = new JsonArray();
        int resolved = 0;
        for (int index=0;index<inventory.size();index++) {
            PcodeOp operation = inventory.get(index);
            if (operation.getOpcode()!=PcodeOp.INDIRECT) continue;
            if (operation.getNumInputs()!=2) throw new IllegalArgumentException("indirect_effect_operand_shape");
            Varnode reference = operation.getInput(1);
            JsonObject row = new JsonObject();
            row.addProperty("operation",exported.get(index).getAsJsonObject().get("id").getAsString());
            row.addProperty("reference_varnode",exported.get(index).getAsJsonObject().getAsJsonArray("inputs").get(1).getAsString());
            row.addProperty("reference_id",new java.math.BigInteger(Long.toUnsignedString(reference.getOffset())));
            JsonObject effect = null;
            String status;
            if (Long.compareUnsigned(reference.getOffset(),0xffffffffL)>0) status="reference_out_of_range";
            else {
                PcodeOp target = high.getOpRef((int)reference.getOffset());
                if (target==null) status="unavailable";
                else {
                    String identity = identities.get(target.getSeqnum());
                    if (identity==null) status="outside_inventory";
                    else {
                        status="resolved"; resolved++;
                        effect = new JsonObject();
                        effect.addProperty("operation",identity);
                        effect.addProperty("opcode",target.getMnemonic());
                        JsonObject sequence = new JsonObject();
                        sequence.addProperty("pc",target.getSeqnum().getTarget().toString(true));
                        sequence.addProperty("time",Integer.toUnsignedLong(target.getSeqnum().getTime()));
                        sequence.addProperty("order",target.getSeqnum().getOrder());
                        effect.add("sequence",sequence);
                    }
                }
            }
            row.addProperty("status",status);row.add("effect",effect);entries.add(row);
        }
        StringBuilder digest = new StringBuilder();
        for (byte part : MessageDigest.getInstance("SHA-256").digest(irBytes)) digest.append(String.format("%02x",part & 255));
        JsonObject observation = new JsonObject();
        observation.addProperty("schema","observed-indirect-effects.v1");
        observation.addProperty("stage","high_function_after_decompilation");
        observation.addProperty("target_sha256",hash.toLowerCase());
        observation.addProperty("function_address",function.getEntryPoint().toString(true));
        observation.addProperty("source_ir_sha256",digest.toString());
        observation.addProperty("total",entries.size());observation.addProperty("resolved",resolved);
        observation.addProperty("unresolved",entries.size()-resolved);observation.addProperty("complete",resolved==entries.size());
        observation.add("entries",entries);observation.addProperty("alias_semantics_proved",false);
        observation.addProperty("call_semantics_proved",false);
        if (new GsonBuilder().disableHtmlEscaping().create().toJson(observation).getBytes(StandardCharsets.UTF_8).length>256*1024)
            throw new IllegalArgumentException("indirect_effect_payload_budget");
        return observation;
    }

    private JsonObject observedVariableStorage(Parameter parameter, boolean includeOrdinal) {
        JsonObject value = new JsonObject();
        if (includeOrdinal) value.addProperty("ordinal", parameter.getOrdinal());
        value.addProperty("name", parameter.getName());
        value.addProperty("type_name", parameter.getDataType().getName());
        value.addProperty("type_size", parameter.getDataType().getLength());
        value.addProperty("source", parameter.getSource().name());
        value.addProperty("auto_parameter", parameter.isAutoParameter());
        value.addProperty("forced_indirect", parameter.isForcedIndirect());
        VariableStorage storage = parameter.getVariableStorage();
        JsonObject layout = new JsonObject();
        layout.addProperty("size", storage.size());
        layout.addProperty("unassigned", storage.isUnassignedStorage());
        layout.addProperty("void", storage.isVoidStorage());
        layout.addProperty("bad", storage.isBadStorage());
        JsonArray pieces = new JsonArray();
        if (storage.getVarnodeCount() > 16) throw new IllegalArgumentException("parameter_storage_piece_budget");
        for (Varnode piece : storage.getVarnodes()) {
            JsonObject item = new JsonObject();
            item.addProperty("space", piece.getAddress().getAddressSpace().getName());
            item.addProperty("offset", Long.toUnsignedString(piece.getOffset(),16));
            item.addProperty("size", piece.getSize());
            pieces.add(item);
        }
        layout.add("pieces",pieces); value.add("storage",layout); return value;
    }

    private JsonObject observedFunctionStorage(Function function) {
        Parameter[] parameters = function.getParameters();
        if (parameters.length > 128) throw new IllegalArgumentException("parameter_storage_count_budget");
        JsonObject observation = new JsonObject();
        observation.addProperty("schema","observed-function-storage.v1");
        observation.addProperty("function_address",function.getEntryPoint().toString(true));
        observation.addProperty("signature_source",function.getSignatureSource().name());
        String convention = function.getCallingConventionName();
        observation.addProperty("convention",convention == null ? "unknown" : convention);
        observation.addProperty("custom_storage",function.hasCustomVariableStorage());
        observation.addProperty("variadic",function.hasVarArgs());
        observation.addProperty("abi_recovered",false);
        JsonArray arguments = new JsonArray();
        for (Parameter parameter : parameters) arguments.add(observedVariableStorage(parameter,true));
        observation.add("parameters",arguments);
        observation.add("return_value",observedVariableStorage(function.getReturn(),false));
        return observation;
    }
    private static final int MAX_FUNCTIONS = 50000;

    private JsonObject observedHighParameters(HighFunction high, Function function, String hash, JsonObject ir) {
        java.util.HashSet<String> identities = new java.util.HashSet<>();
        for (com.google.gson.JsonElement node : ir.getAsJsonArray("varnodes"))
            identities.add(node.getAsJsonObject().get("id").getAsString());
        ghidra.program.model.pcode.LocalSymbolMap local = high.getLocalSymbolMap();
        if (local.getNumParams() > 128) throw new IllegalArgumentException("high_parameter_count_budget");
        JsonObject observation = new JsonObject();
        observation.addProperty("schema","observed-high-parameters.v1");
        observation.addProperty("stage","high_function_after_decompilation");
        observation.addProperty("target_sha256",hash.toLowerCase());
        observation.addProperty("function_address",function.getEntryPoint().toString(true));
        observation.addProperty("abi_recovered",false);
        observation.addProperty("source_parameter_count_proved",false);
        observation.addProperty("call_semantics_proved",false);
        JsonArray parameters = new JsonArray();
        int totalInstances = 0;
        for (int i=0; i<local.getNumParams(); i++) {
            ghidra.program.model.pcode.HighSymbol symbol = local.getParamSymbol(i);
            if (symbol == null) throw new IllegalArgumentException("high_parameter_symbol_missing");
            JsonObject row = new JsonObject();
            row.addProperty("ordinal",i);
            row.addProperty("category_index",symbol.getCategoryIndex());
            row.addProperty("name",symbol.getName());
            row.addProperty("type_name",symbol.getDataType().getName());
            row.addProperty("size",symbol.getSize());
            row.addProperty("is_parameter",symbol.isParameter());
            row.addProperty("hidden_return",symbol.isHiddenReturn());
            row.addProperty("this_pointer",symbol.isThisPointer());
            row.addProperty("type_locked",symbol.isTypeLocked());
            row.addProperty("name_locked",symbol.isNameLocked());
            ghidra.program.model.pcode.HighVariable variable = symbol.getHighVariable();
            JsonObject instances = new JsonObject();
            instances.addProperty("available",variable != null);
            JsonArray observed = new JsonArray();
            int total = 0;
            if (variable != null) {
                Varnode[] members = variable.getInstances();
                if (members == null || members.length > 32768)
                    throw new IllegalArgumentException("high_parameter_instance_budget");
                total = members.length;
                for (Varnode member : members) {
                    if (member instanceof VarnodeAST) {
                        String identity = "v" + ((VarnodeAST)member).getUniqueId();
                        if (identities.contains(identity)) observed.add(identity);
                    }
                }
            }
            totalInstances += total;
            if (totalInstances > 32768) throw new IllegalArgumentException("high_parameter_total_instance_budget");
            instances.addProperty("total",total);
            instances.addProperty("omitted",total-observed.size());
            instances.add("observed",observed);
            row.add("instances",instances); parameters.add(row);
        }
        observation.add("parameters",parameters);
        if (new GsonBuilder().disableHtmlEscaping().create().toJson(observation).getBytes(StandardCharsets.UTF_8).length > 256*1024)
            throw new IllegalArgumentException("high_parameter_payload_budget");
        return observation;
    }
    private static final int MAX_FILE = 2 * 1024 * 1024;
    private static final int MAX_SUMMARY = 8 * 1024 * 1024;
    private static final int MAX_PAYLOAD = 56 * 1024 * 1024;
    protected boolean legacyTypeInjectionRequested() { return false; }

    private String spaceKind(AddressSpace space) {
        if (space.isConstantSpace()) return "constant";
        if (space.isRegisterSpace()) return "register";
        if (space.isUniqueSpace()) return "unique";
        if (space.isStackSpace()) return "stack";
        if (space.isMemorySpace()) return "memory";
        return "other";
    }

    private String variable(Varnode value, LinkedHashMap<String,JsonObject> nodes,
                            Map<SequenceNumber,String> operations, LinkedHashMap<String,AddressSpace> spaces) {
        String id;
        if (value instanceof VarnodeAST) id = "v" + ((VarnodeAST)value).getUniqueId();
        else if (value.isConstant()) id = "c:" + value.getSize() + ":" + Long.toUnsignedString(value.getOffset(),16);
        else throw new IllegalArgumentException("high_pcode_varnode_identity_unavailable");
        if (nodes.containsKey(id)) return id;
        if (nodes.size() >= 32768) throw new IllegalArgumentException("high_pcode_varnode_budget");
        AddressSpace space = value.getAddress().getAddressSpace();
        spaces.put(space.getName(), space);
        JsonObject node = new JsonObject();
        node.addProperty("id",id);
        node.addProperty("space",space.getName());
        node.addProperty("kind",spaceKind(space));
        node.addProperty("offset",Long.toUnsignedString(value.getOffset(),16));
        node.addProperty("size",value.getSize());
        node.addProperty("input",value.isInput());
        node.addProperty("free",value.isFree());
        node.addProperty("persistent",value.isPersistent());
        node.addProperty("unaffected",value.isUnaffected());
        node.addProperty("addr_tied",value.isAddrTied());
        PcodeOp definition = value.getDef();
        if (definition != null) {
            String definitionId = operations.get(definition.getSeqnum());
            if (definitionId == null) throw new IllegalArgumentException("high_pcode_definition_outside_inventory");
            node.addProperty("definition",definitionId);
        }
        nodes.put(id,node);
        return id;
    }

    private JsonObject structuredPcode(HighFunction high, Function function, String hash) {
        ArrayList<PcodeBlockBasic> blocks = high.getBasicBlocks();
        if (blocks.size() > 512) throw new IllegalArgumentException("high_pcode_block_budget");
        Map<SequenceNumber,String> operationIds = new HashMap<>();
        int totalEdges = 0;
        for (PcodeBlockBasic block : blocks) {
            totalEdges += block.getOutSize();
            if (totalEdges > 4096) throw new IllegalArgumentException("high_pcode_edge_budget");
            Iterator<PcodeOp> operations = block.getIterator();
            while (operations.hasNext()) {
                PcodeOp operation = operations.next();
                if (operationIds.size() >= 8192) throw new IllegalArgumentException("high_pcode_operation_budget");
                String id = "o" + operationIds.size();
                if (operationIds.put(operation.getSeqnum(),id) != null) throw new IllegalArgumentException("high_pcode_sequence_duplicate");
            }
        }
        JsonObject document = new JsonObject();
        document.addProperty("schema","ghidra-high-pcode.v1");
        document.addProperty("target_sha256",hash.toLowerCase());
        document.addProperty("function_address",function.getEntryPoint().toString(true));
        document.addProperty("semantic_equivalence_proved",false);
        document.addProperty("binary_semantics_recovered",false);
        document.addProperty("original_source_recovered",false);
        JsonArray blockRecords = new JsonArray();
        JsonArray operationRecords = new JsonArray();
        LinkedHashMap<String,JsonObject> varnodes = new LinkedHashMap<>();
        LinkedHashMap<String,AddressSpace> spaces = new LinkedHashMap<>();
        AddressSpace defaultSpace = currentProgram.getAddressFactory().getDefaultAddressSpace();
        spaces.put(defaultSpace.getName(),defaultSpace);
        String entry = null;
        int entryCandidates = 0;
        for (PcodeBlockBasic block : blocks) {
            String blockId = "b" + block.getIndex();
            if (block.contains(function.getEntryPoint())) { entry = blockId; entryCandidates++; }
            JsonObject record = new JsonObject();
            record.addProperty("id",blockId);
            record.addProperty("start",block.getStart().toString(true));
            record.addProperty("stop",block.getStop().toString(true));
            JsonArray predecessors = new JsonArray();
            JsonArray successors = new JsonArray();
            JsonArray members = new JsonArray();
            for (int slot=0;slot<block.getInSize();slot++) {
                JsonObject edge = new JsonObject();
                edge.addProperty("block","b"+block.getIn(slot).getIndex());
                edge.addProperty("source_slot",block.getInRevIndex(slot));
                predecessors.add(edge);
            }
            for (int slot=0;slot<block.getOutSize();slot++) {
                JsonObject edge = new JsonObject();
                edge.addProperty("block","b"+block.getOut(slot).getIndex());
                edge.addProperty("target_slot",block.getOutRevIndex(slot));
                successors.add(edge);
            }
            record.add("predecessors",predecessors);
            record.add("successors",successors);
            PcodeOp last = block.getLastOp();
            if (last != null && last.getOpcode()==PcodeOp.CBRANCH && block.getOutSize()==2) {
                record.addProperty("false_out","b"+block.getFalseOut().getIndex());
                record.addProperty("true_out","b"+block.getTrueOut().getIndex());
            }
            Iterator<PcodeOp> operations = block.getIterator();
            while (operations.hasNext()) {
                PcodeOp operation = operations.next();
                String operationId = operationIds.get(operation.getSeqnum());
                members.add(operationId);
                if (operation.getNumInputs()>512) throw new IllegalArgumentException("high_pcode_operand_budget");
                JsonObject op = new JsonObject();
                op.addProperty("id",operationId);
                op.addProperty("opcode",operation.getMnemonic());
                JsonObject sequence = new JsonObject();
                sequence.addProperty("pc",operation.getSeqnum().getTarget().toString(true));
                sequence.addProperty("time",Integer.toUnsignedLong(operation.getSeqnum().getTime()));
                sequence.addProperty("order",operation.getSeqnum().getOrder());
                op.add("sequence",sequence);
                JsonArray inputs = new JsonArray();
                for (int slot=0;slot<operation.getNumInputs();slot++) inputs.add(variable(operation.getInput(slot),varnodes,operationIds,spaces));
                op.add("inputs",inputs);
                if (operation.getOutput()!=null) op.addProperty("output",variable(operation.getOutput(),varnodes,operationIds,spaces));
                if (operation.getOpcode()==PcodeOp.MULTIEQUAL) {
                    JsonArray phi = new JsonArray();
                    for (int slot=0;slot<block.getInSize();slot++) phi.add("b"+block.getIn(slot).getIndex());
                    op.add("phi_predecessors",phi);
                }
                operationRecords.add(op);
            }
            record.add("operations",members);
            blockRecords.add(record);
        }
        if (entryCandidates==1) document.addProperty("entry_block",entry);
        document.addProperty("complete",entryCandidates==1);
        document.add("blocks",blockRecords);
        document.add("operations",operationRecords);
        JsonArray variables = new JsonArray();
        for (JsonObject node : varnodes.values()) variables.add(node);
        document.add("varnodes",variables);
        JsonObject context = new JsonObject();
        context.addProperty("language_id",currentProgram.getLanguageID().toString());
        context.addProperty("compiler_spec_id",currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        context.addProperty("endian",currentProgram.getLanguage().isBigEndian()?"big":"little");
        context.addProperty("address_bits",defaultSpace.getSize());
        context.addProperty("image_base",currentProgram.getImageBase().toString(true));
        JsonArray spaceRecords = new JsonArray();
        for (AddressSpace space : spaces.values()) {
            JsonObject description = new JsonObject();
            description.addProperty("name",space.getName());
            description.addProperty("id",space.getSpaceID());
            description.addProperty("kind",spaceKind(space));
            description.addProperty("bits",space.getSize());
            description.addProperty("word_size",space.getAddressableUnitSize());
            spaceRecords.add(description);
        }
        context.add("spaces",spaceRecords);
        document.add("context",context);
        return document;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1 || args[0].isBlank()) throw new IllegalArgumentException("private_output_required");
        Path out = Path.of(args[0]);
        Files.createDirectories(out.resolve("functions"));
        Files.createDirectories(out.resolve("pcode"));
        Files.createDirectories(out.resolve("ir"));
        ArrayList<Function> inventory = new ArrayList<>();
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            if (inventory.size() >= MAX_FUNCTIONS) throw new IllegalArgumentException("function_budget_exceeded");
            inventory.add(iterator.next());
        }
        String inputHash = currentProgram.getExecutableSHA256();
        if (inputHash == null || !inputHash.matches("[0-9a-fA-F]{64}")) throw new IllegalArgumentException("loaded_input_hash_required");
        JsonObject summary = new JsonObject();
        summary.addProperty("schema", "aetherre-ghidra-export.v2");
        summary.addProperty("target_sha256", inputHash.toLowerCase());
        summary.addProperty("program", currentProgram.getName());
        JsonObject policy = new JsonObject();
        policy.addProperty("mode", "observed_program_types");
        policy.addProperty("external_types_injected", false);
        policy.addProperty("legacy_type_injection_requested", legacyTypeInjectionRequested());
        policy.addProperty("type_recovery_proved", false);
        summary.add("type_policy", policy);
        JsonArray records = new JsonArray();
        boolean complete = true;
        boolean payloadExhausted = false;
        int count = 0, successful = 0, payloadBytes = 0;
        DecompInterface decompiler = new DecompInterface();
        decompiler.setOptions(new DecompileOptions());
        try {
            if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException("decompiler_open_failed");
            for (Function function : inventory) {
                JsonObject record = new JsonObject();
                record.addProperty("name", function.getName());
                record.addProperty("address", function.getEntryPoint().toString(true));
                record.addProperty("params", function.getParameterCount());
                record.add("storage_observation", observedFunctionStorage(function));
                record.addProperty("return_type", function.getReturnType().getName());
                record.addProperty("signature", function.getSignature().getPrototypeString());
                record.addProperty("signature_source", function.getSignatureSource().name());
                record.addProperty("success", false);
                records.add(record);
                String stem = String.format("f%06d", count++);
                if (monitor.isCancelled() || payloadExhausted) {
                    complete = false;
                    record.addProperty("attempted", false);
                    record.addProperty("error", payloadExhausted ? "artifact_budget_exceeded" : "cancelled");
                    continue;
                }
                record.addProperty("attempted", true);
                DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
                if (!result.decompileCompleted() || result.getDecompiledFunction() == null) {
                    record.addProperty("error", result.getErrorMessage());
                    continue;
                }
                String source = result.getDecompiledFunction().getC();
                if (source == null || source.isBlank()) {
                    record.addProperty("error", "empty_decompiled_source");
                    continue;
                }
                byte[] sourceBytes = source.getBytes(StandardCharsets.UTF_8);
                StringBuilder pcode = new StringBuilder();
                HighFunction high = result.getHighFunction();
                if (high != null) {
                    Iterator<PcodeOpAST> operations = high.getPcodeOps();
                    while (operations.hasNext() && pcode.length() <= MAX_FILE) pcode.append(operations.next().toString()).append('\n');
                }
                byte[] pcodeBytes = pcode.toString().getBytes(StandardCharsets.UTF_8);
                byte[] irBytes = new byte[0];
                JsonObject highParameterObservation = null;
                JsonObject indirectEffectObservation = null;
                if (high != null) {
                    try {
                        JsonObject structured = structuredPcode(high,function,inputHash);
                        highParameterObservation = observedHighParameters(high,function,inputHash,structured);
                        irBytes = new GsonBuilder().create().toJson(structured).getBytes(StandardCharsets.UTF_8);
                        indirectEffectObservation = observedIndirectEffects(high,function,inputHash,structured,irBytes);
                    } catch (IllegalArgumentException exception) {
                        complete = false;
                        record.addProperty("error",exception.getMessage());
                        continue;
                    }
                }
                if (sourceBytes.length > MAX_FILE || pcodeBytes.length > MAX_FILE || irBytes.length > MAX_FILE ||
                    (long)payloadBytes + sourceBytes.length + pcodeBytes.length + irBytes.length > MAX_PAYLOAD) {
                    complete = false;
                    payloadExhausted = true;
                    record.addProperty("error", "artifact_budget_exceeded");
                    continue;
                }
                String sourceFile = "functions/" + stem + ".c";
                Files.write(out.resolve(sourceFile), sourceBytes, StandardOpenOption.CREATE_NEW);
                record.addProperty("source_file", sourceFile);
                if (high != null) {
                    String pcodeFile = "pcode/" + stem + ".txt";
                    Files.write(out.resolve(pcodeFile), pcodeBytes, StandardOpenOption.CREATE_NEW);
                    record.addProperty("pcode_file", pcodeFile);
                    String irFile = "ir/" + stem + ".json";
                    Files.write(out.resolve(irFile), irBytes, StandardOpenOption.CREATE_NEW);
                    record.addProperty("ir_file",irFile);
                    record.add("high_parameter_observation",highParameterObservation);
                    record.add("indirect_effect_observation",indirectEffectObservation);
                }
                payloadBytes += sourceBytes.length + pcodeBytes.length + irBytes.length;
                record.addProperty("success", true);
                successful++;
            }
        } finally {
            decompiler.dispose();
        }
        summary.add("functions", records);
        summary.addProperty("total_functions", inventory.size());
        summary.addProperty("decompiled_functions", successful);
        summary.addProperty("failed_functions", inventory.size() - successful);
        summary.addProperty("complete", complete && !monitor.isCancelled());
        byte[] summaryBytes = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(summary).getBytes(StandardCharsets.UTF_8);
        if (summaryBytes.length > MAX_SUMMARY) throw new IllegalArgumentException("summary_budget_exceeded");
        Files.write(out.resolve("decompilation_summary.json"), summaryBytes, StandardOpenOption.CREATE_NEW);
        println("[AetherRE] Static export: " + successful + "/" + inventory.size() + "; complete_inventory=" + complete);
        println("[AetherRE] Observed types only; no external type injection or original-source/equivalence proof.");
    }
}
