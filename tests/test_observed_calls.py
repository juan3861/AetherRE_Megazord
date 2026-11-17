import runpy
from pathlib import Path
from dataclasses import replace
import pytest
from aether_re.observed_calls import inventory_observed_calls

def exported(monkeypatch,opcode='CALL'):
    import aether_re.ghidra_headless_bridge as bridge
    from aether_re.ghidra_pcode_ir import analyze_high_pcode
    f=runpy.run_path(str(Path(__file__).with_name('test_ghidra_interface_contract.py')))
    calls,identity=f['fake_export'](monkeypatch,with_ir=True)
    result=bridge.GhidraHeadlessBridge().decompile_binary('own.dll');info=result.functions[identity]
    helpers=runpy.run_path(str(Path(__file__).with_name('test_ghidra_pcode_ir.py')))
    data=info.pcode_ir
    target=helpers['variable']('target','memory' if opcode=='CALL' else 'register',8,offset='402000',input=opcode=='CALLIND')
    if opcode=='CALLOTHER':target=helpers['variable']('target','constant',4,offset='7')
    data['varnodes'].append(target)
    data['operations'][0].update(opcode=opcode,inputs=['target','v0','v1'])
    checked=analyze_high_pcode(data,expected_target=result.target_sha256,expected_address=info.address,evidence_sha256='b'*64)
    result.functions[identity]=replace(info,pcode_ir=data,normalized_ir=checked['graph'],ir_analysis=checked['summary'])
    callee=bridge.GhidraFunctionInfo('callee','ram:402000',False,2,'unsigned int',function_id='a'*64+'!ram:402000')
    result.functions[callee.function_id]=callee;result.total_functions=2
    return result,identity

def test_direct_target_and_operands_are_observed_without_inventing_abi(monkeypatch):
    result,identity=exported(monkeypatch)
    report=inventory_observed_calls(result)
    assert report['total_functions']==2 and report['functions_with_verified_ir']==1 and report['functions_without_ir']==1
    row=report['calls'][0]
    assert row['caller_id']==identity and row['target_id']=='a'*64+'!ram:402000'
    assert row['resolution']=='inventory_address_match' and row['callee_name']=='callee'
    assert row['arguments']==[dict(slot=0,varnode='v0',bits=32),dict(slot=1,varnode='v1',bits=32)]
    assert row['return_bits']==32 and row['abi_recovered'] is False and row['call_executed'] is False
    assert report['complete'] is False and report['call_semantics_proved'] is False

@pytest.mark.parametrize('opcode,kind',[('CALLIND','indirect'),('CALLOTHER','user_operation')])
def test_non_direct_call_never_uses_operand_as_function_address(monkeypatch,opcode,kind):
    result,identity=exported(monkeypatch,opcode)
    row=inventory_observed_calls(result)['calls'][0]
    assert row['kind']==kind and row['target_id'] is None and row['resolution']=='unresolved'
    if opcode=='CALLOTHER':assert row['user_operation_index']==7

def test_ir_mutation_aborts_inventory_instead_of_reusing_stale_graph(monkeypatch):
    result,identity=exported(monkeypatch)
    result.functions[identity].pcode_ir['operations'][0]['inputs'].pop()
    with pytest.raises(ValueError,match='changed'):inventory_observed_calls(result)

def test_call_budget_is_explicit_and_never_reports_complete_when_truncated(monkeypatch):
    result,identity=exported(monkeypatch)
    report=inventory_observed_calls(result,max_calls=0)
    assert report['calls']==[] and report['truncated'] is True and report['complete'] is False
    with pytest.raises(ValueError):inventory_observed_calls(result,max_calls=True)

def test_compound_storage_and_forced_indirection_preserve_observation_not_type_equivalence():
    from aether_re.observed_calls import validate_function_storage
    template=runpy.run_path(str(Path(__file__).with_name('test_ghidra_export_contract.py')))['storage_observation']()
    import copy
    parameter=copy.deepcopy(template['return_value']);parameter.update(ordinal=0,name='hidden',type_name='large_struct',type_size=32,forced_indirect=True,auto_parameter=True)
    parameter['storage']=dict(size=8,unassigned=False,void=False,bad=False,
        pieces=[dict(space='register',offset='8',size=4),dict(space='register',offset='10',size=4)])
    template['parameters']=[parameter]
    assert validate_function_storage(template,address='ram:401000',parameter_count=1,signature_source='ANALYSIS')==template
    assert template['abi_recovered'] is False

@pytest.mark.parametrize('bad',['overlap','oversized','source','boolean_ordinal'])
def test_storage_extra_boundaries_are_rejected(bad):
    from aether_re.observed_calls import validate_function_storage
    template=runpy.run_path(str(Path(__file__).with_name('test_ghidra_export_contract.py')))['storage_observation']()
    if bad=='overlap':template['return_value']['storage'].update(size=8,pieces=[dict(space='register',offset='0',size=4),dict(space='register',offset='2',size=4)])
    elif bad=='oversized':template['return_value']['storage']['pieces']*=17
    elif bad=='source':template['signature_source']='USER_DEFINED'
    else:template['parameters']=[dict(ordinal=False,**template['return_value'])]
    with pytest.raises(ValueError,match='storage_observation'):
        validate_function_storage(template,address='ram:401000',parameter_count=1 if bad=='boolean_ordinal' else 0,signature_source='ANALYSIS')
