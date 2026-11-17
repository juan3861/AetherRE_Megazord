"""Negative public admission and binding, no target execution."""
import copy,dataclasses,hashlib,json,runpy
from pathlib import Path
from aether_re.ghidra_headless_bridge import GhidraFunctionInfo
from aether_re.ghidra_pcode_ir import analyze_high_pcode

def fixture():return runpy.run_path(str(Path(__file__).with_name('test_stack_parameter_interfaces.py')))

def test_stack_profile_requires_actual_amd64_pe_not_only_claimed_ir_context(tmp_path):
    f=fixture();export=f['export_case'](tmp_path);old=export.get_unique_function('owned_sum6')
    target=Path(export.binary_path);binary=bytearray(target.read_bytes());header=int.from_bytes(binary[60:64],'little')
    binary[header+4:header+6]=(0xaa64).to_bytes(2,'little');target.write_bytes(binary)
    digest=hashlib.sha256(binary).hexdigest();data=copy.deepcopy(old.pcode_ir);high=copy.deepcopy(old.high_parameter_observation)
    data['target_sha256']=high['target_sha256']=digest
    evidence=hashlib.sha256(json.dumps(data,sort_keys=True).encode()).hexdigest()
    analysis=analyze_high_pcode(data,expected_target=digest,expected_address=old.address,evidence_sha256=evidence)
    fresh=GhidraFunctionInfo('owned_sum6',old.address,True,6,'ulonglong',function_id=digest+'!'+old.address,
        pcode_ir=data,ir_analysis=analysis['summary'],normalized_ir=analysis['graph'],high_parameter_observation=high)
    export.target_sha256=digest;export.functions={fresh.function_id:fresh}
    report=export.select_reconstruction('owned_sum6',memory_model='bounded-bytes.v2',call_model=f['MODEL'])
    assert report['status']=='unsupported'
    assert 'stack_parameter_machine' in report['errors'][0] or 'memory_pe_machine_unsupported' in report['errors'][0]

def test_reordered_stack_symbol_membership_cannot_authorize_wrong_slot(tmp_path):
    f=fixture();export=f['export_case'](tmp_path);old=export.get_unique_function('owned_sum6')
    high=copy.deepcopy(old.high_parameter_observation)
    high['parameters'][4]['instances'],high['parameters'][5]['instances']=high['parameters'][5]['instances'],high['parameters'][4]['instances']
    changed=dataclasses.replace(old,high_parameter_observation=high);export.functions={changed.function_id:changed}
    report=export.select_reconstruction('owned_sum6',memory_model='bounded-bytes.v2',call_model=f['MODEL'])
    assert report['status']=='unsupported' and 'stack_parameter_location' in report['errors'][0]

def test_bound_high_observation_changes_stack_proof_and_runtime_context(tmp_path):
    f=fixture();export=f['export_case'](tmp_path);old=export.get_unique_function('owned_sum6')
    first=export.select_reconstruction('owned_sum6',memory_model='bounded-bytes.v2',call_model=f['MODEL'])
    high=copy.deepcopy(old.high_parameter_observation);high['parameters'][4]['name']='observed_fifth_value'
    changed=dataclasses.replace(old,high_parameter_observation=high);export.functions={changed.function_id:changed}
    second=export.select_reconstruction('owned_sum6',memory_model='bounded-bytes.v2',call_model=f['MODEL'])
    assert first['status']==second['status']=='complete'
    assert first['call_model']['context_sha256']!=second['call_model']['context_sha256']
    a=first['call_model']['functions'][0]['stack_parameter_proof'];b=second['call_model']['functions'][0]['stack_parameter_proof']
    assert a['source_observation_sha256']!=b['source_observation_sha256']
    assert a['input_layout']==b['input_layout']
