"""A distinct direct-call profile is required for shared abstract-byte effects."""
from copy import deepcopy
from pathlib import Path
import runpy
import pytest

from aether_re.call_closure import reconstruct_direct_call_closure,validate_call_configuration

f=runpy.run_path(str(Path(__file__).with_name('test_call_closure.py')))
MODEL='bounded-direct-effects-calls.v1'


def memory_export(tmp_path,*,other_space=False):
    export=f['make_export'](tmp_path)
    # Native address space is64bits; the scalar helper starts with32bit values.
    for name in ('caller','callee'):
        body=deepcopy(export.get_unique_function(name).pcode_ir)
        next(v for v in body['varnodes'] if v['id']=='v0')['size']=8
        observed=deepcopy(export.get_unique_function(name).high_parameter_observation)
        observed['parameters'][0]['size']=8
        observed['parameters'][0]['instances']=dict(available=True,total=1,omitted=0,observed=['v0'])
        if name=='callee':
            # Keep a valid intermediate body while rebuilding the LOAD/STORE form.
            body['operations'][0].update(opcode='COPY',inputs=['v1'])
        f['replace_function'](export,name,body,observed)
    data=deepcopy(export.get_unique_function('callee').pcode_ir)
    variable=f['helpers']['variable'];operation=f['helpers']['operation'];address=data['function_address']
    next(v for v in data['varnodes'] if v['id']=='v2')['definition']='o1'
    data['varnodes'].append(variable('loaded',definition='o0',offset='20'))
    data['operations']=[operation('o0','LOAD',['c0','v0'],'loaded',pc=address),
        operation('o1','INT_ADD',['loaded','v1'],'v2',pc=address,time=1),
        operation('o2','STORE',['c0','v0','v2'],pc=address,time=2),
        operation('o3','RETURN',['c0','v2'],pc=address,time=3)]
    data['blocks'][0]['operations']=['o0','o1','o2','o3']
    if other_space:
        extra=dict(name='rom',id=4,bits=64,word_size=1,kind='memory')
        caller=deepcopy(export.get_unique_function('caller').pcode_ir)
        caller['context']['spaces'].append(extra)
        f['replace_function'](export,'caller',caller)
        data['context']['spaces'].append(extra)
        data['varnodes'].append(variable('other_selector','constant',8,'4'))
        data['operations'][0]['inputs'][0]='other_selector'
        data['operations'][2]['inputs'][0]='other_selector'
    f['replace_function'](export,'callee',data)
    return export


def alias_export(tmp_path):
    export=memory_export(tmp_path);data=deepcopy(export.get_unique_function('caller').pcode_ir)
    variable=f['helpers']['variable'];operation=f['helpers']['operation'];address=data['function_address']
    next(v for v in data['varnodes'] if v['id']=='v2')['definition']='o1'
    for name,definition,offset in [('before','o0','20'),('after','o2','24'),('scaled_before','o3','28'),
        ('scaled_after','o4','2c'),('combined','o5','30'),('answer','o6','34')]:
        data['varnodes'].append(variable(name,definition=definition,offset=offset))
    data['varnodes'].extend([variable('seven','constant',4,'7'),variable('three','constant',4,'3')])
    data['operations']=[operation('o0','LOAD',['c0','v0'],'before',pc=address),
        operation('o1','CALL',['callee','v0','v1'],'v2',pc=address,time=1),
        operation('o2','LOAD',['c0','v0'],'after',pc=address,time=2),
        operation('o3','INT_MULT',['before','seven'],'scaled_before',pc=address,time=3),
        operation('o4','INT_MULT',['after','three'],'scaled_after',pc=address,time=4),
        operation('o5','INT_ADD',['scaled_before','scaled_after'],'combined',pc=address,time=5),
        operation('o6','INT_ADD',['combined','v2'],'answer',pc=address,time=6),
        operation('o7','RETURN',['c0','answer'],pc=address,time=7)]
    data['blocks'][0]['operations']=[o['id'] for o in data['operations']]
    f['replace_function'](export,'caller',data)
    return export


def test_effect_fixture_is_valid_before_new_profile_admission(tmp_path):
    export=memory_export(tmp_path)
    report=export.select_reconstruction('callee',memory_model='bounded-bytes.v2')
    assert report['status']=='complete',report
    assert report['memory_model']['memory_reads']==report['memory_model']['memory_writes']==1


def test_pure_call_profile_still_refuses_memory_effects(tmp_path):
    report=reconstruct_direct_call_closure(memory_export(tmp_path),'caller')
    assert report['status']=='unsupported' and report['errors']==['call_closure_effects_profile']


def test_effects_profile_is_explicit_and_requires_sparse_runtime():
    validate_call_configuration(MODEL,'bounded-bytes.v2','caller')
    for memory,selector in [(None,'caller'),('bounded-bytes.v1','caller'),('bounded-bytes.v2',None)]:
        with pytest.raises(ValueError,match='requires_sparse_reconstruction'):
            validate_call_configuration(MODEL,memory,selector)


def test_direct_effects_profile_composes_shared_memory_and_provenance(tmp_path):
    report=reconstruct_direct_call_closure(memory_export(tmp_path),'caller',call_model=MODEL)
    assert report['status']=='complete',report
    assert report['call_model']['schema']==MODEL
    assert [p['name'] for p in report['runtime_parameters']]==['aether_memory','aether_calls','aether_effects']
    assert report['effect_model']['schema']=='bounded-operation-start-trace.v1'
    assert report['effect_model']['event_limit']==1000000
    operations=report['effect_model']['memory_operations']
    assert [o['kind'] for o in operations]==['LOAD','STORE']
    assert len({o['token'] for o in operations})==2
    assert all(o['token']==o['function_index']*1024+o['operation_index'] for o in operations)
    assert report['effect_model']['static_memory_reads']==report['effect_model']['static_memory_writes']==1
    assert report['structured_c_source'].count('struct aether_effect_event {')==1
    assert report['abi_recovered'] is report['call_semantics_proved'] is report['binary_equivalence_proved'] is False


def test_effects_profile_refuses_a_nondefault_memory_selector(tmp_path):
    report=reconstruct_direct_call_closure(memory_export(tmp_path,other_space=True),'caller',call_model=MODEL)
    assert report['status']=='unsupported' and report['errors']==['call_closure_memory_space']


def test_effects_profile_does_not_remove_special_return_checks(tmp_path):
    export=memory_export(tmp_path);data=deepcopy(export.get_unique_function('callee').pcode_ir)
    data['varnodes'].append(f['helpers']['variable']('halt','constant',8,'1'))
    data['operations'][-1]['inputs'][0]='halt';f['replace_function'](export,'callee',data)
    report=reconstruct_direct_call_closure(export,'caller',call_model=MODEL)
    assert report['status']=='unsupported'
    assert any('pcode_c_unmodeled_return_target_or_halt' in e for e in report['errors'])
