import hashlib
import json
import os
from pathlib import Path

import pytest
import aether_re.ghidra_headless_bridge as module


@pytest.fixture
def export_job(tmp_path,monkeypatch):
    home=tmp_path/'ghidra';jdk=tmp_path/'jdk'
    for base,name in ((home,'support/analyzeHeadless.bat'),(home,'Ghidra/Framework/Utility/lib/Utility.jar'),(jdk,'bin/java.exe')):
        path=base/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'fixture')
    target=tmp_path/'owned.bin';target.write_bytes(b'owned static fixture')
    digest=hashlib.sha256(target.read_bytes()).hexdigest()
    def execute(items,**changes):
        def bounded(command,**kwargs):
            out=Path(command[-1]);(out/'functions').mkdir()
            records=[]
            for index,item in enumerate(items):
                item=dict(item)
                structured_ir=item.pop('_ir',None)
                hardlink=item.pop('_hardlink',None)
                source=item.pop('_source',f'int f{index}(void){{return {index};}}\n')
                if item.get('success',True):
                    item.setdefault('source_file',f'functions/f{index}.c')
                    if hardlink is not None: os.link(hardlink,out/f'functions/f{index}.c')
                    elif source is not None: (out/f'functions/f{index}.c').write_text(source,encoding='utf-8')
                records.append(dict(params=0,return_type='int',signature_source='ANALYSIS',signature='int f(void)',**item))
                if structured_ir is not None:
                    structured_ir=dict(structured_ir,target_sha256=digest,function_address=item['address'])
                    (out/'ir').mkdir(exist_ok=True)
                    (out/f'ir/f{index}.json').write_text(json.dumps(structured_ir),encoding='utf-8')
                    records[-1]['ir_file']=f'ir/f{index}.json'
            summary=dict(schema='aetherre-ghidra-export.v2',target_sha256=digest,complete=True,
                total_functions=len(records),decompiled_functions=sum(r.get('success',True) for r in records),
                type_policy={'mode':'observed_program_types','external_types_injected':False,'legacy_type_injection_requested':False},functions=records)
            summary.update(changes)
            (out/'decompilation_summary.json').write_text(json.dumps(summary),encoding='utf-8')
            return dict(returncode=0,stdout='',stderr='',timed_out=False,resource_exceeded=False,capture_complete=True,process_tree_contained=True)
        monkeypatch.setattr(module,'run_bounded',bounded)
        return module.GhidraHeadlessBridge(home,jdk).decompile_binary(target,temp_work_dir=tmp_path/'jobs')
    return execute


def function(name='same',address='ram:401000',**kwargs):
    return dict(name=name,address=address,success=True,**kwargs)

def storage_observation():
    variable=dict(name='return',type_name='int',type_size=4,source='ANALYSIS',auto_parameter=False,forced_indirect=False,
        storage=dict(size=4,unassigned=False,void=False,bad=False,pieces=[dict(space='register',offset='0',size=4)]))
    return dict(schema='observed-function-storage.v1',function_address='ram:401000',signature_source='ANALYSIS',
        convention='__fastcall',custom_storage=False,variadic=False,parameters=[],return_value=variable,abi_recovered=False)

def test_export_preserves_observed_storage_without_promoting_abi(export_job):
    observed=storage_observation()
    result=export_job([function(storage_observation=observed)])
    assert result.success
    assert next(iter(result.functions.values())).storage_observation==observed

@pytest.mark.parametrize('change',[
    lambda d:d.update(function_address='ram:402000'),
    lambda d:d.update(abi_recovered=True),
    lambda d:d.update(custom_storage=1),
    lambda d:d['return_value']['storage'].update(unassigned=True),
    lambda d:d['return_value']['storage'].update(size=8),
    lambda d:d['return_value']['storage']['pieces'][0].update(size=True),
    lambda d:d.update(parameters=[dict(ordinal=1,**d['return_value'])]),
])
def test_storage_observation_contradictions_fail_closed(export_job,change):
    observed=storage_observation();change(observed)
    result=export_job([function(storage_observation=observed)])
    assert not result.success and result.status=='failed'
    assert 'ghidra_storage_observation_invalid' in result.error_message

def test_reconstruction_exposes_observed_binding_and_preserves_extra_inputs(export_job):
    import runpy
    data=runpy.run_path(str(Path(__file__).with_name('test_ghidra_pcode_ir.py')))['scalar_ir']()
    result=export_job([function(storage_observation=storage_observation(),_ir=data)])
    assert result.success
    info=next(iter(result.functions.values()))
    selected=result.select_reconstruction(info.function_id)
    assert selected['storage_input_binding']['unbound_inputs']==['v0','v1']
    assert selected['storage_input_binding']['complete'] is False
    assert selected['abi_recovered'] is False

def test_mutated_storage_payload_cannot_be_reused_for_reconstruction(export_job):
    import runpy
    data=runpy.run_path(str(Path(__file__).with_name('test_ghidra_pcode_ir.py')))['scalar_ir']()
    result=export_job([function(storage_observation=storage_observation(),_ir=data)])
    info=next(iter(result.functions.values()));info.storage_observation['return_value']['name']='changed'
    with pytest.raises(ValueError,match='storage_observation_changed'):result.select_reconstruction(info.function_id)


def test_same_name_functions_keep_distinct_identity_and_sources(export_job):
    result=export_job([function(),function(address='ram:402000')])
    assert result.success
    assert len(result.functions)==result.total_functions==result.decompiled_functions==2
    assert len({info.decompiled_c for info in result.functions.values()})==2
    assert result.get_unique_function('same') is None
    assert all(key.startswith(result.target_sha256+'!ram:') for key in result.functions)


@pytest.mark.parametrize('changes',[
    {'decompiled_functions':0},{'total_functions':2},{'target_sha256':'0'*64},
    {'schema':'legacy'},{'complete':'true'},{'total_functions':True},
])
def test_inconsistent_or_unbound_export_never_succeeds(export_job,changes):
    result=export_job([function()],**changes)
    assert not result.success
    assert result.error_message
    assert result.worker_execution['returncode']==0


def test_source_is_required_for_successful_function(export_job):
    result=export_job([function(_source=None)])
    assert not result.success


def test_duplicate_address_even_with_different_spelling_is_rejected(export_job):
    result=export_job([function(),function(name='other',address='ram:00401000')])
    assert not result.success


def test_source_path_cannot_escape_private_output(export_job):
    result=export_job([function(source_file='../input/owned.bin')])
    assert not result.success


def test_partial_denominator_and_valid_sources_survive_failed_functions(export_job):
    result=export_job([function(name='ok'),dict(name='failed',address='ram:402000',success=False,error='timeout')])
    assert result.success is False
    assert result.status=='partial'
    assert result.total_functions==2 and result.decompiled_functions==1
    assert len(result.functions)==2
    assert result.get_unique_function('ok').decompiled_c


def test_missing_or_empty_inventory_cannot_be_complete_success(export_job):
    result=export_job([])
    assert not result.success


def test_source_artifact_limit_is_enforced_before_read(export_job,monkeypatch):
    monkeypatch.setattr(module,'MAX_SOURCE_BYTES',32,raising=False)
    result=export_job([function(_source='/*'+'x'*100+'*/\nint f(void){return 0;}')])
    assert not result.success


def test_unproven_external_injection_cannot_be_reported_as_observed_types(export_job):
    result=export_job([function()],type_policy={'mode':'observed_program_types','external_types_injected':True})
    assert not result.success


def test_hardlink_to_external_file_cannot_be_attested_as_private_artifact(export_job,tmp_path):
    outside=tmp_path/'outside.c';outside.write_text('int outside(void){return 9;}')
    result=export_job([function(_hardlink=outside)])
    assert not result.success


def test_type_recovery_claim_not_proved_by_export_cannot_be_forwarded(export_job):
    result=export_job([function()],type_policy={'mode':'observed_program_types','external_types_injected':False,
        'legacy_type_injection_requested':False,'type_recovery_proved':True})
    assert not result.success


def test_failed_function_count_must_be_integer_not_boolean(export_job):
    result=export_job([function(name='ok'),dict(name='failed',address='ram:402000',success=False,error='timeout')],failed_functions=True)
    assert result.status=='failed'
    assert not result.functions


def test_deferred_postscript_uses_private_source_snapshot(tmp_path,monkeypatch):
    home=tmp_path/'ghidra';jdk=tmp_path/'jdk';scripts=tmp_path/'scripts'
    scripts.mkdir()
    for name in ('DecompileAllFunctions.java','DecompileWithTypeInjection.java'):
        (scripts/name).write_text('/* original trusted exporter */')
    for base,name in ((home,'support/analyzeHeadless.bat'),(home,'Ghidra/Framework/Utility/lib/Utility.jar'),(jdk,'bin/java.exe')):
        path=base/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'fixture')
    target=tmp_path/'owned.bin';target.write_bytes(b'fixture')
    observed=[]
    def bounded(command,**kwargs):
        selected=Path(command[command.index('-scriptPath')+1])
        (scripts/'DecompileAllFunctions.java').write_text('/* changed after launch */')
        observed.append((selected/'DecompileAllFunctions.java').read_text())
        return dict(returncode=1,stdout='',stderr='',timed_out=False,resource_exceeded=False,capture_complete=True,process_tree_contained=True)
    monkeypatch.setattr(module,'run_bounded',bounded)
    result=module.GhidraHeadlessBridge(home,jdk,scripts).decompile_binary(target,temp_work_dir=tmp_path/'jobs')
    assert observed==['/* original trusted exporter */']
    assert result.worker_execution['producer_sha256']['DecompileAllFunctions.java']==hashlib.sha256(observed[0].encode()).hexdigest()


def test_structured_ir_is_validated_and_attached_to_the_function(export_job):
    import runpy
    data=runpy.run_path(str(Path(__file__).with_name('test_ghidra_pcode_ir.py')))['scalar_ir']()
    result=export_job([function(_ir=data)])
    assert result.success
    info=result.get_unique_function('same')
    assert info.ir_analysis['operations']==2
    assert info.normalized_ir['function_id']==info.function_id
    assert info.pcode_ir['target_sha256']==result.target_sha256


def test_bad_structured_ir_cannot_hide_behind_valid_c_source(export_job):
    import runpy
    data=runpy.run_path(str(Path(__file__).with_name('test_ghidra_pcode_ir.py')))['scalar_ir']()
    data['varnodes'][2]['size']=8
    result=export_job([function(_ir=data)])
    assert not result.success


def test_admitted_storage_cannot_be_removed_before_reconstruction(export_job):
    import runpy
    data=runpy.run_path(str(Path(__file__).with_name('test_ghidra_pcode_ir.py')))['scalar_ir']()
    result=export_job([function(_ir=data,storage_observation=storage_observation())])
    assert result.success
    result.get_unique_function('same').storage_observation=None
    with pytest.raises(ValueError,match='ghidra_storage_observation_changed'):
        result.select_reconstruction('same')


def high_parameter_observation():
    import runpy
    observation=runpy.run_path(str(Path(__file__).with_name('test_high_parameters.py')))['high_observation']()
    observation['target_sha256']=hashlib.sha256(b'owned static fixture').hexdigest()
    return observation


def test_export_preserves_separate_post_decompilation_parameter_observation(export_job):
    import runpy
    data=runpy.run_path(str(Path(__file__).with_name('test_ghidra_pcode_ir.py')))['scalar_ir']()
    observed=high_parameter_observation()
    result=export_job([function(_ir=data,high_parameter_observation=observed)])
    assert result.success
    info=result.get_unique_function('same')
    assert info.high_parameter_observation==observed and info.params==0
    assert len(observed['parameters'])==2  # Different stages need not agree in count.


def test_reconstruction_publishes_post_decompilation_associations(export_job):
    import runpy
    data=runpy.run_path(str(Path(__file__).with_name('test_ghidra_pcode_ir.py')))['scalar_ir']()
    result=export_job([function(_ir=data,high_parameter_observation=high_parameter_observation())])
    report=result.select_reconstruction('same')['high_parameter_input_associations']
    assert report['complete'] is True and report['source_parameter_count_proved'] is False


def test_high_parameter_observation_requires_its_ir_inventory(export_job):
    result=export_job([function(high_parameter_observation=high_parameter_observation())])
    assert not result.success and 'high_parameter_observation_without_ir' in result.error_message


@pytest.mark.parametrize('mutation',['edit','remove'])
def test_admitted_high_parameter_observation_cannot_change(export_job,mutation):
    import runpy
    data=runpy.run_path(str(Path(__file__).with_name('test_ghidra_pcode_ir.py')))['scalar_ir']()
    result=export_job([function(_ir=data,high_parameter_observation=high_parameter_observation())])
    assert result.success
    info=result.get_unique_function('same')
    if mutation=='remove':info.high_parameter_observation=None
    else:info.high_parameter_observation['parameters'][0]['name']='changed'
    with pytest.raises(ValueError,match='high_parameter_observation_changed'):
        result.select_reconstruction('same')


@pytest.mark.parametrize('mutation',[
    lambda d:d.update(target_sha256='0'*64),lambda d:d.update(stage='before'),
    lambda d:d['parameters'][0]['instances'].update(observed=['missing'],total=1),
])
def test_invalid_high_parameter_observation_fails_the_export(export_job,mutation):
    import runpy
    data=runpy.run_path(str(Path(__file__).with_name('test_ghidra_pcode_ir.py')))['scalar_ir']()
    observed=high_parameter_observation();mutation(observed)
    result=export_job([function(_ir=data,high_parameter_observation=observed)])
    assert not result.success and 'high_parameter_observation_invalid' in result.error_message
