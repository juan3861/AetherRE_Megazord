"""Contract RED outside frozen source inventory; copy into tests after full rehash."""
import runpy
from pathlib import Path
import pytest
from aether_re.ghidra_pcode_c import reconstruct_high_pcode,_MEMORY_RUNTIME

ROOT=Path.cwd();f=runpy.run_path(str(ROOT/'tests/test_ghidra_pcode_memory.py'))

def reconstruct(data,**options):
    return reconstruct_high_pcode(data,expected_target=f['f']['TARGET'],expected_address=f['f']['ADDRESS'],
        evidence_sha256=f['f']['EVIDENCE'],memory_model='bounded-bytes.v2',**options)

@pytest.mark.parametrize('endian',['little','big'])
@pytest.mark.parametrize('store',[False,True])
def test_explicit_v2_lowers_to_sparse_state_and_keeps_effect_counts(endian,store):
    result=reconstruct(f['memory_ir'](store,endian))
    assert result['status']=='complete',result['errors']
    assert result['memory_model']['schema']=='bounded-bytes.v2'
    assert result['memory_model']['region_limit']==128 and result['memory_model']['byte_limit']==1048576
    assert result['runtime_parameters']==[dict(name='aether_memory',c_type='struct aether_sparse_memory *')]
    assert result['memory_model']['memory_reads']==1 and result['memory_model']['memory_writes']==int(store)
    assert result['memory_model']['abstract_addresses_are_host_pointers'] is False
    assert 'aether_sparse_memory_load' in result['structured_c_source']
    assert 'aether_recovered(struct aether_sparse_memory *aether_memory' in result['structured_c_source']
    if store:assert 'aether_sparse_memory_store' in result['structured_c_source']

def test_v1_output_prefix_and_parameter_layout_remain_unchanged():
    result=f['reconstruct'](f['memory_ir'](),memory_model='bounded-bytes.v1')
    assert result['status']=='complete' and result['structured_c_source'].startswith(_MEMORY_RUNTIME+'\n')
    assert result['runtime_parameters']==[dict(name='aether_memory',c_type='struct aether_memory *')]

def test_sparse_scalar_and_empty_cycle_still_have_step_guards():
    result=reconstruct(f['empty_cycle_ir']())
    assert result['status']=='complete',result['errors']
    assert result['memory_model']['empty_block_steps']==['loop']
    assert 'aether_sparse_memory_step' in result['structured_c_source']

def test_sparse_helper_names_cannot_be_shadowed_by_recovered_function():
    result=reconstruct(f['memory_ir'](),function_name='aether_sparse_memory_load')
    assert result['status']=='invalid' and result['structured_c_source'] is None
