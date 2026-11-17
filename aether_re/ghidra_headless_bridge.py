"""Bounded static Ghidra export, with input/address identity and inventory.

Decompiled C is not original source. Observed program types are not a proof
of type recovery, and an export is not semantic equivalence.
"""

from __future__ import annotations

import json
import hashlib
import os
import re
import stat
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from aether_re.process import run_bounded
from aether_re.evidence import create_verified_snapshot
from aether_re.ghidra_pcode_ir import analyze_high_pcode

MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_SUMMARY_BYTES = 8 * 1024 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_FUNCTIONS = 50000


def publish_export_output(path: Path, content: str) -> str:
    """Publish new CLI output through the existing verified snapshot protocol."""
    payload = content.encode("utf-8", errors="strict")
    if len(payload) > MAX_ARTIFACT_BYTES:
        raise ValueError("ghidra_publication_budget_exceeded")
    with tempfile.TemporaryDirectory(prefix="aether-export-publication-") as directory:
        source = Path(directory) / "payload"
        source.write_bytes(payload)
        return create_verified_snapshot(source, path, max_bytes=MAX_ARTIFACT_BYTES)


def _ordinary(path):
    info = path.lstat()
    if (path.is_symlink() or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            or (stat.S_ISREG(info.st_mode) and info.st_nlink != 1)):
        raise ValueError("ghidra_artifact_link_rejected")
    return info


def _load_export(out_dir, target_sha256):
    """Validate a terminated worker's private artifact set before publication."""
    _ordinary(out_dir)
    files, total_bytes = set(), 0
    for path in out_dir.rglob("*"):
        info = _ordinary(path)
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("ghidra_nonregular_artifact")
        total_bytes += info.st_size
        if total_bytes > MAX_ARTIFACT_BYTES or len(files) >= 3 * MAX_FUNCTIONS + 1:
            raise ValueError("ghidra_artifact_budget_exceeded")
        files.add(path.relative_to(out_dir).as_posix())
    hashes, used = {}, set()

    def read(name, limit):
        if name not in files or name in used:
            raise ValueError("ghidra_artifact_missing_or_reused")
        path = out_dir / name
        if _ordinary(path).st_size > limit:
            raise ValueError("ghidra_artifact_size_exceeded")
        with path.open("rb") as handle:
            data = handle.read(limit + 1)
        if len(data) > limit:
            raise ValueError("ghidra_artifact_size_exceeded")
        hashes[name] = hashlib.sha256(data).hexdigest()
        used.add(name)
        return data.decode("utf-8", errors="strict")

    def no_duplicate_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("ghidra_duplicate_json_key")
            result[key] = value
        return result

    data = json.loads(read("decompilation_summary.json", MAX_SUMMARY_BYTES), object_pairs_hook=no_duplicate_keys,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite_json")))
    if (not isinstance(data, dict) or data.get("schema") != "aetherre-ghidra-export.v2"
            or data.get("target_sha256") != target_sha256 or type(data.get("complete")) is not bool):
        raise ValueError("ghidra_export_schema_identity_or_completeness_invalid")
    policy = data.get("type_policy")
    if (not isinstance(policy, dict) or policy.get("mode") != "observed_program_types"
            or policy.get("external_types_injected") is not False
            or policy.get("type_recovery_proved", False) is not False
            or set(policy) - {"mode", "external_types_injected", "type_recovery_proved", "legacy_type_injection_requested"}
            or type(policy.get("legacy_type_injection_requested")) is not bool):
        raise ValueError("ghidra_type_provenance_invalid")
    records = data.get("functions")
    if not isinstance(records, list) or len(records) > MAX_FUNCTIONS:
        raise ValueError("ghidra_function_inventory_invalid")
    for key in ("total_functions", "decompiled_functions"):
        if type(data.get(key)) is not int or not 0 <= data[key] <= MAX_FUNCTIONS:
            raise ValueError("ghidra_denominator_invalid")
    if data["total_functions"] != len(records):
        raise ValueError("ghidra_total_inventory_disagreement")
    functions, sources, pcodes = {}, [], []
    for item in records:
        if not isinstance(item, dict):
            raise ValueError("ghidra_function_record_invalid")
        name, address = item.get("name"), item.get("address")
        match = re.fullmatch(r"([A-Za-z0-9_.-]{1,64}):([0-9a-fA-F]{1,32})", address or "")
        if (not isinstance(name, str) or not name or len(name) > 4096 or match is None
                or type(item.get("success")) is not bool or type(item.get("params")) is not int
                or not 0 <= item["params"] <= 4096
                or item.get("signature_source") not in {"DEFAULT", "IMPORTED", "ANALYSIS", "USER_DEFINED"}
                or not isinstance(item.get("signature"), str) or len(item["signature"]) > 16384
                or not isinstance(item.get("return_type"), str) or len(item["return_type"]) > 4096):
            raise ValueError("ghidra_function_metadata_invalid")
        address = match[1] + ":" + format(int(match[2], 16), "x")
        function_id = target_sha256 + "!" + address
        if function_id in functions:
            raise ValueError("ghidra_duplicate_function_address")
        source, pcode, structured_ir = None, None, None
        ir_analysis, normalized_ir = {}, {}
        if item["success"]:
            source_file = item.get("source_file")
            if not isinstance(source_file, str) or not re.fullmatch(r"functions/[A-Za-z0-9_-]+\.c", source_file):
                raise ValueError("ghidra_source_path_invalid")
            source = read(source_file, MAX_SOURCE_BYTES)
            if not source.strip():
                raise ValueError("ghidra_success_without_source")
            sources.append("// FunctionId: " + function_id + "\n" + source + "\n")
            if item.get("pcode_file") is not None:
                if not isinstance(item["pcode_file"], str) or not re.fullmatch(r"pcode/[A-Za-z0-9_-]+\.txt", item["pcode_file"]):
                    raise ValueError("ghidra_pcode_path_invalid")
                pcode = read(item["pcode_file"], MAX_SOURCE_BYTES)
                pcodes.append("### " + function_id + "\n" + pcode)
            if item.get("ir_file") is not None:
                if not isinstance(item["ir_file"], str) or not re.fullmatch(r"ir/[A-Za-z0-9_-]+\.json", item["ir_file"]):
                    raise ValueError("ghidra_ir_path_invalid")
                structured_ir = json.loads(read(item["ir_file"], MAX_SOURCE_BYTES), object_pairs_hook=no_duplicate_keys,
                    parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite_json")))
                analyzed = analyze_high_pcode(structured_ir, expected_target=target_sha256, expected_address=address,
                                              evidence_sha256=hashes[item["ir_file"]])
                ir_analysis, normalized_ir = analyzed["summary"], analyzed["graph"]
        elif item.get("source_file") is not None or item.get("pcode_file") is not None or item.get("ir_file") is not None:
            raise ValueError("ghidra_failed_function_with_published_source")
        storage_observation=None
        if 'storage_observation' in item:
            from aether_re.observed_calls import validate_function_storage
            storage_observation=validate_function_storage(item['storage_observation'],address=address,
                parameter_count=item['params'],signature_source=item['signature_source'])
        high_parameter_observation = None
        if 'high_parameter_observation' in item:
            if structured_ir is None:
                raise ValueError('high_parameter_observation_without_ir')
            from aether_re.high_parameters import validate_high_parameters
            high_parameter_observation = validate_high_parameters(item['high_parameter_observation'],
                data=structured_ir, expected_target=target_sha256, expected_address=address)
        indirect_effect_observation = None
        if 'indirect_effect_observation' in item:
            if structured_ir is None:
                raise ValueError('indirect_effect_observation_without_ir')
            from aether_re.indirect_effects import validate_indirect_effects
            indirect_effect_observation = validate_indirect_effects(item['indirect_effect_observation'],
                data=structured_ir,expected_target=target_sha256,expected_address=address,
                evidence_sha256=ir_analysis['source_ir_sha256'])
        functions[function_id] = GhidraFunctionInfo(name, address, item["success"], item["params"], item["return_type"],
            decompiled_c=source, signature=item["signature"], signature_source=item["signature_source"],
            error_message=item.get("error"), function_id=function_id, pcode_ir=structured_ir,
            ir_analysis=ir_analysis, normalized_ir=normalized_ir,storage_observation=storage_observation,
            high_parameter_observation=high_parameter_observation,indirect_effect_observation=indirect_effect_observation)
    successful = sum(info.success for info in functions.values())
    failed = data.get("failed_functions", len(functions) - successful)
    if type(failed) is not int or data["decompiled_functions"] != successful or failed != len(functions) - successful:
        raise ValueError("ghidra_success_inventory_disagreement")
    if files != used:
        raise ValueError("ghidra_unreferenced_artifacts")
    complete = data["complete"] and bool(functions) and successful == len(functions)
    return functions, "".join(sources), "\n".join(pcodes), policy, hashes, complete


@dataclass
class GhidraFunctionInfo:
    name: str
    address: str
    success: bool
    params: int
    return_type: str
    decompiled_c: Optional[str] = None
    pcode_ops: List[str] = field(default_factory=list)
    function_id: str = ""
    signature: str = ""
    signature_source: str = "DEFAULT"
    error_message: Optional[str] = None
    pcode_ir: Optional[Dict[str, Any]] = None
    ir_analysis: Dict[str, Any] = field(default_factory=dict)
    normalized_ir: Dict[str, Any] = field(default_factory=dict)
    storage_observation: Optional[Dict[str, Any]] = None
    high_parameter_observation: Optional[Dict[str, Any]] = None
    indirect_effect_observation: Optional[Dict[str, Any]] = None
    pcode_payload_sha256: str = field(init=False, default="")

    def __post_init__(self):
        self._indirect_effect_observation_sha256 = hashlib.sha256(json.dumps(self.indirect_effect_observation,
            sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')).hexdigest()
        self._high_parameter_observation_sha256 = hashlib.sha256(json.dumps(self.high_parameter_observation,
            sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')).hexdigest()
        self._storage_observation_sha256 = hashlib.sha256(json.dumps(self.storage_observation,sort_keys=True,
            separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')).hexdigest()
        if self.pcode_ir is not None:
            self.pcode_payload_sha256 = hashlib.sha256(json.dumps(self.pcode_ir,sort_keys=True,
                separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')).hexdigest()

    def checked_indirect_effect_observation(self):
        digest=hashlib.sha256(json.dumps(self.indirect_effect_observation,sort_keys=True,
            separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')).hexdigest()
        if digest!=self._indirect_effect_observation_sha256:
            raise ValueError('indirect_effect_observation_changed')
        if self.indirect_effect_observation is None:return None
        current=hashlib.sha256(json.dumps(self.pcode_ir,sort_keys=True,separators=(',',':'),
            ensure_ascii=False,allow_nan=False).encode('utf-8')).hexdigest()
        if current!=self.pcode_payload_sha256:raise ValueError('ghidra_reconstruction_ir_changed')
        from aether_re.indirect_effects import validate_indirect_effects
        return validate_indirect_effects(self.indirect_effect_observation,data=self.pcode_ir,
            expected_target=self.pcode_ir['target_sha256'],expected_address=self.address,
            evidence_sha256=self.ir_analysis['source_ir_sha256'])

    def ir_preview(self):
        indirect=self.checked_indirect_effect_observation()
        if not self.ir_analysis:
            return {"status": "unavailable"}
        keys = ("status", "blocks", "operations", "varnodes", "cfg_edges", "phi_operations", "source_ir_sha256", "semantic_equivalence_proved")
        result={key: self.ir_analysis[key] for key in keys}
        if indirect is not None:
            result['indirect_effects']={key:indirect[key] for key in ('total','resolved','unresolved','complete','alias_semantics_proved')}
        return result


@dataclass
class GhidraDecompilationResult:
    binary_path: str
    success: bool
    total_functions: int
    decompiled_functions: int
    functions: Dict[str, GhidraFunctionInfo]
    full_c_source: str
    high_pcode_text: str
    elapsed_seconds: float
    error_message: Optional[str] = None
    target_sha256: Optional[str] = None
    worker_execution: Dict[str, Any] = field(default_factory=dict)
    artifact_dir: Optional[str] = None
    status: str = "failed"
    type_policy: Dict[str, Any] = field(default_factory=dict)
    artifact_hashes: Dict[str, str] = field(default_factory=dict)
    limitations: List[str] = field(default_factory=lambda: [
        "decompiled C is not original source or semantic equivalence",
        "observed type/signature origin does not prove DWARF/PDB/ABI recovery",
    ])

    def get_unique_function(self, name: str) -> Optional[GhidraFunctionInfo]:
        """A name is a query, never an identity. Ambiguous names abstain."""
        candidates = [info for info in self.functions.values() if info.name == name]
        return candidates[0] if len(candidates) == 1 else None

    def ir_coverage(self):
        valid = sum(info.ir_analysis.get("status") == "structurally_valid" for info in self.functions.values())
        partial = sum(info.ir_analysis.get("status") == "partial" for info in self.functions.values())
        return dict(total_functions=self.total_functions, structurally_valid=valid, partial=partial,
                    unavailable=self.total_functions-valid-partial, semantic_equivalence_proved=False)

    def select_ir_graph(self, selector):
        if not isinstance(selector, str) or not 1 <= len(selector) <= 4096:
            raise ValueError("ghidra_ir_selector_invalid")
        info = self.functions.get(selector) or self.get_unique_function(selector)
        if info is None or not info.normalized_ir:
            raise ValueError("ghidra_ir_unavailable_or_name_ambiguous")
        if len(json.dumps(info.normalized_ir, ensure_ascii=False).encode("utf-8")) > 1024 * 1024:
            raise ValueError("ghidra_ir_selection_output_budget")
        return info.normalized_ir

    def select_observed_frame_program(self, selector, *, target_bytes, language_sources, object_bytes, object_base=0x100000, frame_runtime=None, input_receipt=None):
        """Derive a model from an observed address prefix and requested extent.

        Address-prefix facts and a separate bounded pair-data observation retain
        their own limits. Neither admits a native frame, authenticates a toolchain
        or recovers ABI. Unsupported pair projections carry their own refusal.
        """
        self._validate_frame_runtime(frame_runtime,object_base)
        self.select_reconstruction(selector,memory_model='bounded-bytes.v2')
        root=self.functions.get(selector) or self.get_unique_function(selector)
        if (root is None or not root.success or type(self.target_sha256) is not str
                or root.function_id!=self.target_sha256+'!'+root.address
                or self.functions.get(root.function_id) is not root):
            raise ValueError('ghidra_frame_root_identity_changed')
        from aether_re.native_frame_address import observe_frame_address
        observation=observe_frame_address(data=root.pcode_ir,high=root.high_parameter_observation,
            target_bytes=target_bytes,language_sources=language_sources,object_bytes=object_bytes)
        options={} if frame_runtime is None else dict(frame_runtime=frame_runtime)
        result=self.select_frame_program(selector,observation,object_base=object_base,**options)
        result['native_address_observation']=observation
        result['native_address_prefix_observed']=True
        result['frame_fact_origin']='observed_native_address_prefix_with_requested_extent'
        root,callee=self._validated_frame_pair(selector)
        from .native_caller_data import build_native_pair_observation
        result['native_pair_data_observation']=build_native_pair_observation(
            root=self._frame_snapshot(root),callee=self._frame_snapshot(callee),
            target_bytes=target_bytes,language_sources=language_sources,object_bytes=object_bytes,
            input_receipt=input_receipt)
        return result

    @staticmethod
    def _validate_frame_runtime(frame_runtime,object_base):
        if frame_runtime is not None and (type(frame_runtime) is not str or frame_runtime!='invocation-arena.v1'):
            raise ValueError('ghidra_frame_runtime_invalid')
        if frame_runtime is not None and (type(object_base) is not int or object_base!=0x100000):
            raise ValueError('ghidra_frame_arena_fixed_base_conflict')

    def select_frame_program(self, selector, frame_fact, *, object_base=0x100000, frame_runtime=None):
        """Select a distinct derived model from two revalidated IR snapshots.

        A supplied native fact is a hypothesis, never a call-profile admission.
        Existing reconstruction results and raw IR remain unchanged.
        """
        self._validate_frame_runtime(frame_runtime,object_base)
        if type(frame_fact) is not dict:
            raise ValueError('ghidra_frame_fact_object')
        try:
            encoded=json.dumps(frame_fact,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')
        except (ValueError,TypeError,RecursionError) as error:
            raise ValueError('ghidra_frame_fact_invalid') from error
        if len(encoded)>65536:raise ValueError('ghidra_frame_fact_budget')
        root,callee=self._validated_frame_pair(selector)
        if frame_runtime is None:
            from aether_re.frame_program import build_frame_program
            result=build_frame_program(self._frame_snapshot(root),self._frame_snapshot(callee),json.loads(encoded),object_base=object_base)
        else:
            from aether_re.frame_arena_program import build_frame_arena_program
            result=build_frame_arena_program(self._frame_snapshot(root),self._frame_snapshot(callee),json.loads(encoded))
            result['frame_runtime']=frame_runtime
        result['selected_functions']=dict(root=root.function_id,callee=callee.function_id)
        result['supplied_frame_fact_sha256']=hashlib.sha256(encoded).hexdigest()
        return result

    @staticmethod
    def _frame_snapshot(info):
        return json.loads(json.dumps(dict(pcode_ir=info.pcode_ir,high_parameter_observation=info.high_parameter_observation,
            ir_analysis=info.ir_analysis),sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False))

    def _validated_frame_pair(self,selector):
        # Reuse every intake/digest check even when scalar translation refuses CALL.
        self.select_reconstruction(selector,memory_model='bounded-bytes.v2')
        root=self.functions.get(selector) or self.get_unique_function(selector)
        if root is None or not root.success:raise ValueError('ghidra_frame_root_unavailable')
        if root.function_id!=self.target_sha256+'!'+root.address or self.functions.get(root.function_id) is not root:
            raise ValueError('ghidra_frame_root_identity_changed')
        calls=[op for op in root.pcode_ir['operations'] if op['opcode']=='CALL']
        if len(calls)!=1:raise ValueError('ghidra_frame_requires_one_direct_call')
        nodes={node['id']:node for node in root.pcode_ir['varnodes']}
        target=nodes[calls[0]['inputs'][0]]
        if target['kind']!='memory':raise ValueError('ghidra_frame_direct_callee_required')
        address=target['space']+':'+format(int(target['offset'],16),'x')
        identity=self.target_sha256+'!'+address
        callee=self.functions.get(identity)
        if callee is None or not callee.success:raise ValueError('ghidra_frame_callee_unavailable')
        if callee.function_id!=identity or callee.address!=address:
            raise ValueError('ghidra_frame_callee_identity_changed')
        self.select_reconstruction(identity,memory_model='bounded-bytes.v2')
        return root,callee

    def select_reconstruction(self, selector, *, debug_pdb=None, dia_helper=None, dia_dll=None, debug_report=None, memory_model=None, memory_derivation=None, _memory_context=None, call_model=None):
        """Connect a validated function export to scalar C-Tree reconstruction."""
        from aether_re.call_closure import validate_call_configuration
        validate_call_configuration(call_model,memory_model,selector)
        if memory_model is not None and memory_model not in ('bounded-bytes.v1','bounded-bytes.v2'):
            raise ValueError('ghidra_memory_model_invalid')
        context=_memory_context
        if memory_derivation is not None or context is not None:
            from aether_re.native_memory_custody import AdmittedMemoryContext,admit_memory_context
            if memory_model not in ('bounded-bytes.v1','bounded-bytes.v2') or memory_derivation is not None and context is not None:
                raise ValueError('ghidra_memory_derivation_configuration')
            if memory_derivation is not None:
                if not isinstance(memory_derivation,(str,Path)) or not 1<=len(str(memory_derivation))<=32768 or not str(memory_derivation).strip():
                    raise ValueError('ghidra_memory_derivation_path')
                context=admit_memory_context(memory_derivation)
            if not isinstance(context,AdmittedMemoryContext):raise ValueError('ghidra_memory_context_not_admitted')
            if context.target_sha256!=self.target_sha256:raise ValueError('ghidra_memory_derivation_target_mismatch')
        paths_requested=any(value is not None for value in (debug_pdb,dia_helper,dia_dll))
        if debug_report is not None and paths_requested:
            raise ValueError('ghidra_debug_report_configuration_conflict')
        if paths_requested and any(value is None for value in (debug_pdb,dia_helper,dia_dll)):
            raise ValueError('ghidra_debug_return_requires_pdb_helper_dll')
        self.select_ir_graph(selector)  # same identity/ambiguity/output boundary
        info = self.functions.get(selector) or self.get_unique_function(selector)
        from aether_re.ghidra_pcode_c import reconstruct_high_pcode
        if info.pcode_ir is None or not info.ir_analysis:
            raise ValueError("ghidra_reconstruction_ir_unavailable")
        current = hashlib.sha256(json.dumps(info.pcode_ir,sort_keys=True,separators=(',',':'),
            ensure_ascii=False,allow_nan=False).encode('utf-8')).hexdigest()
        if not info.pcode_payload_sha256 or current != info.pcode_payload_sha256:
            raise ValueError("ghidra_reconstruction_ir_changed")
        checked = analyze_high_pcode(info.pcode_ir, expected_target=self.target_sha256,
            expected_address=info.address,evidence_sha256=info.ir_analysis['source_ir_sha256'])
        if checked['graph'] != info.normalized_ir or checked['summary'] != info.ir_analysis:
            raise ValueError("ghidra_reconstruction_ir_changed")
        indirect_effect_observation=info.checked_indirect_effect_observation()
        storage_binding=None
        stored=hashlib.sha256(json.dumps(info.storage_observation,sort_keys=True,separators=(',',':'),
            ensure_ascii=False,allow_nan=False).encode('utf-8')).hexdigest()
        if stored!=info._storage_observation_sha256:raise ValueError('ghidra_storage_observation_changed')
        if info.storage_observation is not None:
            from aether_re.observed_calls import validate_function_storage,bind_observed_storage
            validate_function_storage(info.storage_observation,address=info.address,parameter_count=info.params,signature_source=info.signature_source)
            storage_binding=bind_observed_storage(info.pcode_ir,info.storage_observation,expected_target=self.target_sha256,
                expected_address=info.address,evidence_sha256=info.ir_analysis['source_ir_sha256'])
        high_parameter_binding = None
        observed_digest = hashlib.sha256(json.dumps(info.high_parameter_observation,sort_keys=True,
            separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')).hexdigest()
        if observed_digest != info._high_parameter_observation_sha256:
            raise ValueError('high_parameter_observation_changed')
        if info.high_parameter_observation is not None:
            from aether_re.high_parameters import bind_high_parameters
            high_parameter_binding = bind_high_parameters(info.pcode_ir,info.high_parameter_observation,
                expected_target=self.target_sha256,expected_address=info.address,
                evidence_sha256=info.ir_analysis['source_ir_sha256'])
        if call_model is not None:
            from aether_re.call_closure import reconstruct_direct_call_closure
            result=reconstruct_direct_call_closure(self,info.function_id,call_model=call_model)
        else:
            result = reconstruct_high_pcode(info.pcode_ir,expected_target=self.target_sha256,
                expected_address=info.address,evidence_sha256=info.ir_analysis['source_ir_sha256'],memory_model=memory_model)
        if indirect_effect_observation is not None:result['indirect_effect_observation']=indirect_effect_observation
        if storage_binding is not None:result['storage_input_binding']=storage_binding
        if high_parameter_binding is not None:result['high_parameter_input_associations']=high_parameter_binding
        if context is not None and result['status']!='complete':
            result['memory_binding']=dict(status='unavailable',code='translation_not_available',process_snapshot_proved=False,binary_equivalence_proved=False)
        if context is not None and result['status']=='complete':
            space=result['memory_model']['space'];base_space,base_offset=info.pcode_ir['context']['image_base'].split(':',1)
            if space['name']!=base_space:raise ValueError('ghidra_memory_derivation_image_space_mismatch')
            bound=context.bind(target_sha256=self.target_sha256,space_id=space['id']&0xffffffff,
                image_base=int(base_offset,16),bits=space['bits'],endian=info.pcode_ir['context']['endian'])
            if not bound['contiguous_runtime_compatible'] and memory_model!='bounded-bytes.v2':raise ValueError('ghidra_memory_derivation_requires_sparse_runtime')
            if memory_model=='bounded-bytes.v2':bound.update(runtime_model=memory_model,runtime_compatible=True)
            result['memory_binding']=bound
        requested=paths_requested or debug_report is not None
        if requested:
            if result['status']!='complete':
                raise ValueError('ghidra_debug_return_requires_scalar_translation')
            from aether_re.pdb_dia import extract_pdb_symbols, pdb_return_contract
            observed=debug_report if debug_report is not None else extract_pdb_symbols(
                Path(debug_pdb),helper_path=Path(dia_helper),dia_dll=Path(dia_dll),binary_path=Path(self.binary_path))
            space,offset=info.address.split(':',1)
            base_space,base_offset=info.pcode_ir['context']['image_base'].split(':',1)
            if space!=base_space:raise ValueError('ghidra_debug_return_address_space_mismatch')
            contract=pdb_return_contract(observed,target_sha256=self.target_sha256,function_rva=int(offset,16)-int(base_offset,16))
            if contract['return_bits']>result['return_bits']:
                raise ValueError('ghidra_debug_return_ir_lacks_return_bits')
            names=[b['parameter'] for b in result['input_bindings']]
            runtime=result.get('runtime_parameters',[])
            parameters=', '.join([p['c_type']+p['name'] for p in runtime]+['unsigned long long '+name for name in names]) or 'void'
            call_names=[p['name'] for p in runtime]+names
            mask=str((1<<contract['return_bits'])-1)+'ULL'
            expr='aether_return_value'
            if contract['signed']:
                sign=str(1<<(contract['return_bits']-1))+'ULL';expr='((aether_return_value ^ '+sign+') - '+sign+')'
            adapter=result['structured_c_source']+'\nunsigned long long aether_debug_return('+parameters+')\n{\n'+\
                '    unsigned long long aether_return_value = '+result['function_name']+'('+', '.join(call_names)+') & '+mask+';\n    return '+expr+';\n}\n'
            result['debug_return_adapter']=dict(status='complete',contract=contract,structured_c_source=adapter,
                input_bindings=result['input_bindings'],output_model='unsigned64 transport of debug-typed scalar return',
                binary_equivalence_proved=False,abi_recovered=False,
                limitations=['only return interpretation; parameter/register mapping and complete ABI remain unproved'])
            if runtime:
                result['debug_return_adapter']['runtime_parameters']=runtime
            if context is not None:
                result['debug_return_adapter']['memory_binding']=result['memory_binding']
            if 'call_model' in result:
                result['debug_return_adapter']['call_model']=result['call_model']
                result['debug_return_adapter']['call_semantics_proved']=False
            if 'effect_model' in result:
                result['debug_return_adapter']['effect_model']=result['effect_model']
        if len(json.dumps(result,ensure_ascii=False).encode('utf-8')) > 1024 * 1024:
            raise ValueError("ghidra_reconstruction_output_budget")
        return result


class GhidraHeadlessBridge:
    """Industrial headless wrapper for NSA Ghidra Decompiler."""

    DEFAULT_GHIDRA_PATH = Path(r"E:\AetherRE_Toolchain\ghidra_12.1.4_PUBLIC")
    DEFAULT_JDK_PATH = Path(r"E:\AetherRE_Toolchain\jdk-21")
    DEFAULT_SCRIPTS_DIR = Path(__file__).resolve().parent / "ghidra_scripts"

    def __init__(
        self,
        ghidra_home: Optional[str | Path] = None,
        jdk_home: Optional[str | Path] = None,
        scripts_dir: Optional[str | Path] = None,
        runtime_lock: Optional[str | Path] = None,
    ):
        self.ghidra_home = Path(ghidra_home) if ghidra_home else self.DEFAULT_GHIDRA_PATH
        self.jdk_home = Path(jdk_home) if jdk_home else self.DEFAULT_JDK_PATH
        self.scripts_dir = Path(scripts_dir) if scripts_dir else self.DEFAULT_SCRIPTS_DIR
        self.runtime_lock = runtime_lock
        self.configured_runtime_roots={'ghidra':str(self.ghidra_home.absolute()),'jdk':str(self.jdk_home.absolute())}
        if runtime_lock is not None:
            # Select physical destinations for installation defaults once. The
            # Java command and both checks use these exact roots, not the alias.
            # Explicit roots still reach the strict no-reparse verifier unchanged.
            self.ghidra_home=self.ghidra_home.resolve(strict=True) if ghidra_home is None else self.ghidra_home.absolute()
            self.jdk_home=self.jdk_home.resolve(strict=True) if jdk_home is None else self.jdk_home.absolute()

        self.headless_bat = self.ghidra_home / "support" / "analyzeHeadless.bat"
        if not self.headless_bat.exists():
            raise FileNotFoundError(f"Ghidra analyzeHeadless.bat not found at: {self.headless_bat}")

    def decompile_binary(
        self,
        binary_path: str | Path,
        timeout_seconds: int = 300,
        temp_work_dir: Optional[str | Path] = None,
        max_cpu: int = 4,
        script_name: str = "DecompileAllFunctions.java",
    ) -> GhidraDecompilationResult:
        """Runs Ghidra headless analysis on target binary, decompiling all functions to C and P-Code."""
        binary = Path(binary_path).resolve()
        if not binary.exists():
            raise FileNotFoundError(f"Target binary not found: {binary}")
        if script_name not in {"DecompileAllFunctions.java", "DecompileWithTypeInjection.java"}:
            raise ValueError("ghidra_export_script_not_supported")

        start_time = time.time()
        cleanup_temp = False

        if temp_work_dir:
            parent_dir = Path(temp_work_dir).resolve()
            parent_dir.mkdir(parents=True, exist_ok=True)
            work_dir = Path(tempfile.mkdtemp(prefix="run-",dir=parent_dir))
        else:
            work_dir = Path(tempfile.mkdtemp(prefix="aether_ghidra_"))
            cleanup_temp = self.runtime_lock is None

        out_dir = work_dir / "output"
        out_dir.mkdir(parents=True, exist_ok=True)
        proj_dir = work_dir / "proj"
        proj_dir.mkdir(parents=True, exist_ok=True)
        proj_name = f"AetherProj_{binary.stem}"

        for limit in (timeout_seconds,max_cpu):
            if type(limit) is not int or limit <= 0:
                raise ValueError("invalid_ghidra_budget")
        if timeout_seconds > 3600 or max_cpu > 16:
            raise ValueError("ghidra_budget_out_of_range")
        java = self.jdk_home / "bin" / ("java.exe" if os.name == "nt" else "java")
        utility = self.ghidra_home / "Ghidra/Framework/Utility/lib/Utility.jar"
        if not java.is_file() or not utility.is_file():
            raise FileNotFoundError("ghidra_direct_java_runtime_incomplete")
        input_dir = work_dir / "input"
        input_dir.mkdir()
        with binary.open("rb") as handle:
            snapshot_bytes = handle.read(512 * 1024 * 1024 + 1)
        if len(snapshot_bytes) > 512 * 1024 * 1024:
            raise ValueError("ghidra_input_budget_exceeded")
        snapshot = input_dir / binary.name
        snapshot.write_bytes(snapshot_bytes)
        input_sha256 = hashlib.sha256(snapshot_bytes).hexdigest()
        script_dir = work_dir / "scripts"
        script_dir.mkdir()
        producer_hashes = {}
        for name in ("DecompileAllFunctions.java", "DecompileWithTypeInjection.java"):
            with (self.scripts_dir / name).open("rb") as handle:
                source = handle.read(1024 * 1024 + 1)
            if len(source) > 1024 * 1024:
                raise ValueError("ghidra_script_budget_exceeded")
            (script_dir / name).write_bytes(source)
            producer_hashes[name] = hashlib.sha256(source).hexdigest()

        env = os.environ.copy()
        for key in ("JAVA_TOOL_OPTIONS","_JAVA_OPTIONS","JDK_JAVA_OPTIONS","CLASSPATH"):
            env.pop(key,None)
        if self.jdk_home.exists():
            env["JAVA_HOME"] = str(self.jdk_home)
            env["PATH"] = f"{self.jdk_home / 'bin'};{env.get('PATH', '')}"

        isolated = {}
        for name in ("home","settings","cache","tmp"):
            isolated[name] = work_dir / name
            isolated[name].mkdir()
        cmd = [
            str(java), "-Djava.awt.headless=true", "-Xmx2G",
            "-Djava.system.class.loader=ghidra.GhidraClassLoader",
            "--enable-native-access=ALL-UNNAMED",
            "-Djavax.xml.accessExternalDTD=", "-Djavax.xml.accessExternalSchema=",
            f"-Duser.home={isolated['home']}",
            f"-Dapplication.settingsdir={isolated['settings']}",
            f"-Dapplication.cachedir={isolated['cache']}",
            f"-Djava.io.tmpdir={isolated['tmp']}",
            "-cp", str(utility), "ghidra.Ghidra", "ghidra.app.util.headless.AnalyzeHeadless",
            str(proj_dir),
            proj_name,
            "-import",
            str(snapshot),
            "-scriptPath",
            str(script_dir),
            "-max-cpu",
            str(max_cpu),
            "-deleteProject",
            "-okToDelete",
            "-postScript",
            script_name,
            str(out_dir),
        ]

        execution: Dict[str, Any] = {}
        try:
            if self.runtime_lock is not None:
                from aether_re.ghidra_runtime_lock import read_ghidra_runtime_lock,verify_ghidra_runtime_lock
                pin=read_ghidra_runtime_lock(self.runtime_lock)
                runtime_snapshot=work_dir/'runtime-lock.json'
                create_verified_snapshot(Path(pin['path']),runtime_snapshot,
                    expected_sha256=pin['raw_sha256'],max_bytes=4*1024**2)
                captured=read_ghidra_runtime_lock(runtime_snapshot)
                if captured['raw_sha256']!=pin['raw_sha256']:raise ValueError('ghidra_runtime_lock_snapshot_changed')
                checks=dict(schema='ghidra-runtime-checks.v1',input_path=pin['path'],
                    raw_sha256=pin['raw_sha256'],snapshot_path=str(runtime_snapshot),
                    configured_roots=dict(self.configured_runtime_roots))
                execution['runtime_lock']=checks
                def refused_check(error):
                    return dict(schema='ghidra-runtime-verification.v1',verified=False,
                        errors=[type(error).__name__+':'+str(error)[:300]],
                        upstream_authenticity_proved=False,continuous_execution_integrity_proved=False,
                        scope='runtime check refused; no positive byte or execution integrity claim')
                try:checks['pre']=verify_ghidra_runtime_lock(captured['manifest'],self.ghidra_home,self.jdk_home)
                except (OSError,ValueError) as error:checks['pre']=refused_check(error)
                if not checks['pre']['verified']:raise ValueError('ghidra_runtime_lock_pre_refused')
            proc = run_bounded(
                cmd,
                env=env,
                stdin=subprocess.DEVNULL,
                timeout=timeout_seconds,
                output_limit_bytes=8 * 1024 * 1024,
                memory_limit_mb=4096,
                require_process_tree=True,
                cwd=str(work_dir),
            )
            elapsed = time.time() - start_time

            execution.update({key:value for key,value in proc.items() if key not in {"stdout","stderr"}})
            execution["producer_sha256"] = producer_hashes
            if self.runtime_lock is not None:
                for name,key in [('worker-stdout.log','stdout'),('worker-stderr.log','stderr')]:
                    with (work_dir/name).open('x',encoding='utf-8') as h:h.write(proc.get(key,''))
                try:
                    captured_after=read_ghidra_runtime_lock(runtime_snapshot)
                    if captured_after['raw_sha256']!=pin['raw_sha256']:raise ValueError('ghidra_runtime_lock_snapshot_changed')
                    checks['post']=verify_ghidra_runtime_lock(captured['manifest'],self.ghidra_home,self.jdk_home)
                except (OSError,ValueError) as error:checks['post']=refused_check(error)
                elapsed=time.time()-start_time
                if not checks['post']['verified']:raise ValueError('ghidra_runtime_lock_post_refused')
            if (proc["returncode"] != 0 or proc.get("timed_out") or proc.get("resource_exceeded")
                    or not proc.get("capture_complete") or not proc.get("process_tree_contained")):
                return GhidraDecompilationResult(
                    str(binary),False,0,0,{},"","",elapsed,
                    error_message=f"Ghidra worker failed: exit={proc['returncode']}, timeout={proc.get('timed_out')}, resource={proc.get('resource_kind')}; {proc.get('stderr','')[-1000:]}",
                    target_sha256=input_sha256,worker_execution=execution,
                    artifact_dir=str(work_dir) if not cleanup_temp else None,
                )

            functions_dict, full_c_source, high_pcode, type_policy, artifact_hashes, complete = _load_export(out_dir, input_sha256)
            successful = sum(info.success for info in functions_dict.values())
            return GhidraDecompilationResult(
                binary_path=str(binary),
                success=complete,
                total_functions=len(functions_dict),
                decompiled_functions=successful,
                functions=functions_dict,
                full_c_source=full_c_source,
                high_pcode_text=high_pcode,
                elapsed_seconds=elapsed,
                target_sha256=input_sha256,worker_execution=execution,
                artifact_dir=str(work_dir) if not cleanup_temp else None,
                status="complete" if complete else "partial", type_policy=type_policy,
                artifact_hashes=artifact_hashes,
                error_message=None if complete else "ghidra_export_incomplete_or_functions_failed",
            )

        except subprocess.TimeoutExpired:
            return GhidraDecompilationResult(
                binary_path=str(binary),
                success=False,
                total_functions=0,
                decompiled_functions=0,
                functions={},
                full_c_source="",
                high_pcode_text="",
                elapsed_seconds=timeout_seconds,
                error_message=f"Ghidra execution timed out after {timeout_seconds}s",
                target_sha256=input_sha256,worker_execution=execution,
                artifact_dir=str(work_dir) if not cleanup_temp else None,
            )
        except Exception as ex:
            return GhidraDecompilationResult(
                binary_path=str(binary),
                success=False,
                total_functions=0,
                decompiled_functions=0,
                functions={},
                full_c_source="",
                high_pcode_text="",
                elapsed_seconds=time.time() - start_time,
                error_message=f"Exception during Ghidra execution: {str(ex)}",
                target_sha256=input_sha256,worker_execution=execution,
                artifact_dir=str(work_dir) if not cleanup_temp else None,
            )
        finally:
            if 'runtime_lock' in execution:
                with (work_dir/'runtime-verification.json').open('x',encoding='utf-8') as h:
                    json.dump(execution['runtime_lock'],h,indent=2)
            if cleanup_temp:
                try:
                    shutil.rmtree(work_dir, ignore_errors=True)
                except Exception:
                    pass
