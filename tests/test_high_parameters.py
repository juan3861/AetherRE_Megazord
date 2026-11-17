"""Post-decompilation observations preserve uncertainty instead of inventing ABI."""
from copy import deepcopy
from pathlib import Path
import runpy
import json
import pytest
from aether_re.high_parameters import validate_high_parameters, bind_high_parameters

f=runpy.run_path(str(Path(__file__).with_name('test_ghidra_pcode_ir.py')))


def high_observation():
    def parameter(i,ids):
        return dict(ordinal=i,category_index=i,name='param_'+str(i+1),type_name='uint',size=4,
            is_parameter=True,hidden_return=False,this_pointer=False,type_locked=False,name_locked=False,
            instances=dict(available=True,total=len(ids),omitted=0,observed=ids))
    return dict(schema='observed-high-parameters.v1',stage='high_function_after_decompilation',
        target_sha256=f['TARGET'],function_address=f['ADDRESS'],parameters=[parameter(0,['v0','v2']),parameter(1,['v1'])],
        abi_recovered=False,source_parameter_count_proved=False,call_semantics_proved=False)


def validate(value):
    return validate_high_parameters(value,data=f['scalar_ir'](),expected_target=f['TARGET'],expected_address=f['ADDRESS'])


def bind(value,data=None):
    return bind_high_parameters(data or f['scalar_ir'](),value,expected_target=f['TARGET'],expected_address=f['ADDRESS'],evidence_sha256=f['EVIDENCE'])


def test_association_uses_real_input_ids_and_never_certifies_source_parameter_count():
    observation=high_observation();before=deepcopy(observation);result=bind(observation)
    assert observation==before
    assert [p['input_varnodes'] for p in result['parameters']]==[['v0'],['v1']]
    assert result['unbound_inputs']==[] and result['complete'] is True
    assert result['abi_recovered'] is result['source_parameter_count_proved'] is result['call_semantics_proved'] is False


def test_missing_instances_remain_missing_without_synthetic_inputs():
    observation=high_observation();observation['parameters'][0]['instances']=dict(available=True,total=0,omitted=0,observed=[])
    result=bind(observation)
    assert result['parameters'][0]['status']=='no_observed_input' and result['unbound_inputs']==['v0']
    assert result['complete'] is False


def test_known_omitted_instances_prevent_complete_inventory_claim():
    observation=high_observation();observation['parameters'][1]['instances']=dict(available=True,total=2,omitted=1,observed=['v1'])
    result=bind(observation)
    assert result['parameters'][1]['input_varnodes']==['v1'] and result['complete'] is False
    assert result['omitted_instances']==1


def test_overlapping_high_symbol_ownership_is_reported_as_ambiguous():
    observation=high_observation();observation['parameters'][1]['instances']=dict(available=True,total=2,omitted=0,observed=['v0','v1'])
    result=bind(observation)
    assert all(p['status']=='ambiguous_input_association' for p in result['parameters'])
    assert result['complete'] is False and result['unbound_inputs']==['v0','v1']


def test_noninput_instances_are_observed_without_becoming_parameters():
    observation=high_observation();observation['parameters'][0]['instances']=dict(available=True,total=1,omitted=0,observed=['v2'])
    result=bind(observation)
    assert result['parameters'][0]['input_varnodes']==[] and result['unbound_inputs']==['v0']


@pytest.mark.parametrize('mutate',[
    lambda d:d.update(schema='invented'),lambda d:d.update(stage='before_decompilation'),
    lambda d:d.update(target_sha256='0'*64),lambda d:d.update(function_address='ram:402000'),
    lambda d:d.update(abi_recovered=True),lambda d:d.update(source_parameter_count_proved=True),
    lambda d:d.update(call_semantics_proved=True),lambda d:d.update(unexpected=1),
    lambda d:d['parameters'][0].update(ordinal=True),lambda d:d['parameters'][0].update(ordinal=1),
    lambda d:d['parameters'][0].update(category_index=True),lambda d:d['parameters'][0].update(name=''),
    lambda d:d['parameters'][0].update(type_name=None),lambda d:d['parameters'][0].update(size=0),
    lambda d:d['parameters'][0].update(hidden_return=1),lambda d:d['parameters'][0].update(is_parameter=False),
    lambda d:d['parameters'][0]['instances'].update(total=3),
    lambda d:d['parameters'][0]['instances'].update(total=True),
    lambda d:d['parameters'][0]['instances'].update(omitted=-1),
    lambda d:d['parameters'][0]['instances'].update(observed=['v0','v0']),
    lambda d:d['parameters'][0]['instances'].update(observed=['v0','missing']),
    lambda d:d['parameters'][0]['instances'].update(observed=['v0',None]),
    lambda d:d['parameters'][0]['instances'].update(available=False),
    lambda d:d['parameters'][0]['instances'].update(available=1),
])
def test_malformed_or_cross_bound_observations_are_rejected(mutate):
    observation=high_observation();mutate(observation)
    with pytest.raises(ValueError,match='high_parameter_observation_invalid'):validate(observation)


def test_binding_revalidates_the_underlying_ir_identity():
    data=f['scalar_ir']();data['target_sha256']='0'*64
    with pytest.raises(ValueError):bind(high_observation(),data)


def test_absent_high_variable_is_distinct_from_a_known_empty_instance_inventory():
    observation=high_observation()
    observation['parameters'][0]['instances']=dict(available=False,total=0,omitted=0,observed=[])
    result=bind(observation)
    assert result['parameters'][0]['instance_enumeration_available'] is False
    assert result['complete'] is False


@pytest.mark.parametrize('mutation',[
    lambda d:d.update(parameters=d['parameters']*65),
    lambda d:d['parameters'][0].update(name='x'*4097),
    lambda d:d['parameters'][0]['instances'].update(total=32769,omitted=32767),
    lambda d:d.update(function_address=[]),
    lambda d:d.update(target_sha256=None),
    lambda d:d['parameters'][0].update(instances=[]),
])
def test_explicit_count_text_and_type_budgets_fail_closed(mutation):
    observation=high_observation();mutation(observation)
    with pytest.raises(ValueError,match='high_parameter_observation_invalid'):validate(observation)


def test_an_empty_observed_inventory_does_not_prove_original_source_arity():
    data=f['scalar_ir']()
    data['varnodes'][0]=f['variable']('v0','constant',offset='1')
    data['varnodes'][1]=f['variable']('v1','constant',offset='2')
    observation=high_observation();observation['parameters']=[]
    result=bind(observation,data)
    assert result['complete'] is True and result['unbound_inputs']==[]
    assert result['source_parameter_count_proved'] is result['abi_recovered'] is False


def budget_observation(name):
    observation=high_observation();template=observation['parameters'][0]
    observation['parameters']=[]
    for ordinal in range(128):
        row=deepcopy(template);row.update(ordinal=ordinal,category_index=ordinal,name=name,
            instances=dict(available=True,total=0,omitted=0,observed=[]))
        observation['parameters'].append(row)
    return observation


def test_compact_producer_budget_is_not_rejected_for_python_separator_spaces():
    observation=budget_observation('x'*1774)
    assert len(json.dumps(observation,ensure_ascii=False,separators=(',',':')).encode())<=256*1024
    assert len(json.dumps(observation,ensure_ascii=False).encode())>256*1024
    assert validate(observation) is observation


@pytest.mark.parametrize('separator',['\u2028','\u2029'])
def test_budget_counts_gson_line_separator_escapes(separator):
    observation=budget_observation(separator*350)
    compact=json.dumps(observation,ensure_ascii=False,separators=(',',':'))
    assert len(compact.encode())<256*1024
    assert len(compact.replace(separator,'\\u'+format(ord(separator),'04x')).encode())>256*1024
    with pytest.raises(ValueError,match='high_parameter_observation_invalid'):validate(observation)
