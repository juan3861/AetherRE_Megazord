"""Post-regression contract tests prepared outside the frozen inventory."""
from copy import deepcopy
from pathlib import Path
import runpy
import pytest
from aether_re.observed_calls import bind_observed_storage

f=runpy.run_path(str(Path.cwd()/'tests/test_ghidra_pcode_ir.py'))
s=runpy.run_path(str(Path.cwd()/'tests/test_ghidra_export_contract.py'))

def observation():
    observed=s['storage_observation']()
    parameter=deepcopy(observed['return_value']);parameter.update(name='x',ordinal=0)
    parameter['storage']['pieces'][0]['offset']='8'
    observed['parameters']=[parameter]
    return observed

def test_binding_preserves_exact_parameter_match_and_unbound_liveins():
    data=f['scalar_ir']();result=bind_observed_storage(data,observation(),expected_target=f['TARGET'],expected_address=f['ADDRESS'],evidence_sha256=f['EVIDENCE'])
    assert result['parameters'][0]['status']=='exact_storage_match'
    assert result['parameters'][0]['pieces'][0]['varnode']=='v0'
    assert result['unbound_inputs']==['v1'] and result['complete'] is False
    assert result['abi_recovered'] is False

def test_mismatched_width_is_reported_without_assigning_a_parameter():
    observed=observation();observed['parameters'][0]['storage']['size']=8
    observed['parameters'][0]['storage']['pieces'][0]['size']=8
    result=bind_observed_storage(f['scalar_ir'](),observed,expected_target=f['TARGET'],expected_address=f['ADDRESS'],evidence_sha256=f['EVIDENCE'])
    assert result['parameters'][0]['status']=='unresolved' and result['unbound_inputs']==['v0','v1']

def test_one_livein_cannot_be_silently_owned_by_two_parameters():
    observed=observation();second=deepcopy(observed['parameters'][0]);second.update(ordinal=1,name='y');observed['parameters'].append(second)
    result=bind_observed_storage(f['scalar_ir'](),observed,expected_target=f['TARGET'],expected_address=f['ADDRESS'],evidence_sha256=f['EVIDENCE'])
    assert all(p['status']=='ambiguous_storage' for p in result['parameters'])
    assert result['complete'] is False

def test_cross_target_or_function_observation_is_rejected():
    with pytest.raises(ValueError):bind_observed_storage(f['scalar_ir'](),observation(),expected_target='0'*64,expected_address=f['ADDRESS'],evidence_sha256=f['EVIDENCE'])
    observed=observation();observed['function_address']='ram:402000'
    with pytest.raises(ValueError):bind_observed_storage(f['scalar_ir'](),observed,expected_target=f['TARGET'],expected_address=f['ADDRESS'],evidence_sha256=f['EVIDENCE'])

def test_signature_source_label_must_be_from_observed_enum():
    observed=observation();observed['signature_source']='INVENTED'
    with pytest.raises(ValueError):bind_observed_storage(f['scalar_ir'](),observed,expected_target=f['TARGET'],expected_address=f['ADDRESS'],evidence_sha256=f['EVIDENCE'])
