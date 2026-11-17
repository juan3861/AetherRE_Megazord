"""Explicit abstract memory hypotheses never become recovered process ABI."""
import runpy
from pathlib import Path

import pytest

from aether_re.ghidra_pcode_c import reconstruct_high_pcode

f=runpy.run_path(str(Path(__file__).with_name('test_ghidra_pcode_ir.py')))


def memory_ir(store=False,endian='little'):
    data=f['scalar_ir']();v=f['variable'];op=f['operation']
    data['context']['endian']=endian
    data['varnodes']=[v('pointer','register',8,offset='8',input=True),v('word','register',4,offset='10',input=True),
        v('space','constant',4,offset='0'),v('ret','constant',8),v('loaded',size=4,definition='load')]
    data['operations']=([op('store','STORE',['space','pointer','word'])] if store else [])+[
        op('load','LOAD',['space','pointer'],'loaded',time=1),op('return','RETURN',['ret','loaded'],time=2)]
    data['blocks'][0]['operations']=[o['id'] for o in data['operations']]
    return data


def reconstruct(data,**kwargs):
    return reconstruct_high_pcode(data,expected_target=f['TARGET'],expected_address=f['ADDRESS'],evidence_sha256=f['EVIDENCE'],**kwargs)


def test_default_scalar_translation_still_abstains_from_memory():
    result=reconstruct(memory_ir())
    assert result['status']=='unsupported' and result['structured_c_source'] is None


@pytest.mark.parametrize('endian',['little','big'])
@pytest.mark.parametrize('store',[False,True])
def test_opt_in_memory_model_keeps_space_width_effects_and_runtime_signature(endian,store):
    result=reconstruct(memory_ir(store,endian),memory_model='bounded-bytes.v1')
    assert result['status']=='complete',result
    model=result['memory_model'];assert model['schema']=='bounded-bytes.v1' and model['endian']==endian
    assert model['space']['name']=='ram' and model['space']['word_size']==1
    assert model['memory_reads']==1 and model['memory_writes']==int(store)
    assert model['abstract_addresses_are_host_pointers'] is False
    assert result['runtime_parameters']==[dict(name='aether_memory',c_type='struct aether_memory *')]
    assert 'struct aether_memory {' in result['structured_c_source']
    assert 'aether_memory_load' in result['structured_c_source']
    assert result['binary_equivalence_proved'] is False and result['abi_recovered'] is False


@pytest.mark.parametrize('word_size',[2,4,8])
def test_nonbyte_addressed_space_requires_its_own_model(word_size):
    data=memory_ir();data['context']['spaces'][0]['word_size']=word_size
    result=reconstruct(data,memory_model='bounded-bytes.v1')
    assert result['status']=='unsupported' and result['structured_c_source'] is None
    assert any('memory' in error for error in result['errors'])


@pytest.mark.parametrize('model',['automatic','host-pointers',{},True])
def test_unknown_memory_model_is_not_silently_ignored(model):
    result=reconstruct(memory_ir(),memory_model=model)
    assert result['status']=='invalid' and result['structured_c_source'] is None


def test_scalar_body_with_memory_context_still_has_a_step_budget():
    result=reconstruct(f['scalar_ir'](),memory_model='bounded-bytes.v1')
    assert result['status']=='complete'
    assert 'aether_memory_step' in result['structured_c_source'] and result['memory_model']['step_limit']==1000000


def test_persistent_storage_is_not_silently_mapped_to_external_bytes():
    data=memory_ir();data['varnodes'][0]['persistent']=True
    result=reconstruct(data,memory_model='bounded-bytes.v1')
    assert result['status']=='unsupported' and result['structured_c_source'] is None


def empty_cycle_ir():
    data=f['scalar_ir']();v=f['variable'];op=f['operation']
    data['varnodes']=[v('input','register',4,input=True),v('zero','constant',4),v('one','constant',4,offset='1'),
        v('condition',size=1,definition='compare'),v('target','memory',8,offset='401010'),v('ret','constant',8)]
    data['operations']=[op('compare','INT_NOTEQUAL',['input','zero'],'condition'),op('branch','CBRANCH',['target','condition'],time=1),
        op('return','RETURN',['ret','one'],pc='ram:401020')]
    data['blocks']=[dict(id='entry',start=f['ADDRESS'],stop=f['ADDRESS'],predecessors=[],
        successors=[dict(block='exit',target_slot=0),dict(block='loop',target_slot=0)],operations=['compare','branch'],true_out='loop',false_out='exit'),
        dict(id='loop',start='ram:401010',stop='ram:401010',predecessors=[dict(block='entry',source_slot=1),dict(block='loop',source_slot=0)],
            successors=[dict(block='loop',target_slot=1)],operations=[]),
        dict(id='exit',start='ram:401020',stop='ram:401020',predecessors=[dict(block='entry',source_slot=0)],successors=[],operations=['return'])]
    data['entry_block']='entry'
    return data


def test_empty_cfg_cycle_is_also_charged_to_memory_step_budget():
    result=reconstruct(empty_cycle_ir(),memory_model='bounded-bytes.v1')
    assert result['status']=='complete',result['errors']
    assert result['memory_model']['empty_block_steps']==['loop']


def test_space_selector_cannot_silently_truncate_metadata_identity():
    data=memory_ir()
    next(s for s in data['context']['spaces'] if s['name']=='ram')['id']=256
    selector=next(v for v in data['varnodes'] if v['id']=='space')
    selector.update(size=1,offset='100')
    result=reconstruct(data,memory_model='bounded-bytes.v1')
    assert result['status']=='unsupported'
    assert 'pcode_c_memory_space_selector_width' in result['errors']
