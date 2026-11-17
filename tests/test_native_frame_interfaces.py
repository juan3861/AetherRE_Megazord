import copy,json,runpy
from pathlib import Path
import pytest
from aether_re.ghidra_headless_bridge import _load_export,GhidraDecompilationResult


def loaded(tmp_path):
    helper=runpy.run_path(str(Path(__file__).with_name('test_native_frame_address.py')))
    raw,root_ir,root_high=helper['sample']()
    fixture=json.loads((Path(__file__).parent/'fixtures/frame_program_ir.json').read_text())
    fixture['root']['pcode_ir']=root_ir;fixture['root']['high_parameter_observation']=root_high
    for key in ('pcode_ir','high_parameter_observation'):fixture['callee'][key]['target_sha256']=root_ir['target_sha256']
    (tmp_path/'functions').mkdir();(tmp_path/'ir').mkdir();rows=[]
    for i,role in enumerate(('root','callee')):
        info=fixture[role];source=f'functions/f{i}.c';irfile=f'ir/f{i}.json';name=role+'_native'
        (tmp_path/source).write_text('unsigned long long source(void){return 0;}')
        (tmp_path/irfile).write_text(json.dumps(info['pcode_ir'],sort_keys=True))
        rows.append(dict(name=name,address=info['pcode_ir']['function_address'],params=len(info['high_parameter_observation']['parameters']),
            return_type='ulonglong',signature_source='ANALYSIS',signature='ulonglong '+name+'(void)',success=True,
            source_file=source,ir_file=irfile,high_parameter_observation=info['high_parameter_observation']))
    summary=dict(schema='aetherre-ghidra-export.v2',target_sha256=root_ir['target_sha256'],complete=True,
        total_functions=2,decompiled_functions=2,failed_functions=0,
        type_policy=dict(mode='observed_program_types',external_types_injected=False,legacy_type_injection_requested=False),functions=rows)
    (tmp_path/'decompilation_summary.json').write_text(json.dumps(summary))
    functions,*_=_load_export(tmp_path,root_ir['target_sha256'])
    exported=GhidraDecompilationResult('not-executed',True,2,2,functions,'','',0,target_sha256=root_ir['target_sha256'])
    return exported,bytes(raw),helper['LANGUAGE']


def test_reader_builds_model_from_observed_address_without_supplied_frame_fact(tmp_path):
    result,raw,language=loaded(tmp_path);before=copy.deepcopy(result)
    report=result.select_observed_frame_program('root_native',target_bytes=raw,language_sources=language,object_bytes=16)
    assert report['status']=='complete' and report['program_kind']=='derived_model'
    assert report['native_address_prefix_observed'] is True and report['native_frame_fact_verified'] is False
    assert report['frame_fact_origin']=='observed_native_address_prefix_with_requested_extent'
    observation=report['native_address_observation']
    assert observation['entry_rsp_offset']==-24 and observation['requested_object_bytes']==16
    assert observation['production_admission'] is False and observation['callee_effect_extent_proved'] is False
    assert report['selected_functions']['callee'].endswith('!ram:180001270')
    assert result==before


@pytest.mark.parametrize('part',['target','native_code','root_ir','root_high','root_id','language'])
def test_reader_refuses_before_model_emission_on_disagreement(tmp_path,monkeypatch,part):
    result,raw,language=loaded(tmp_path);language=copy.deepcopy(language);root=result.get_unique_function('root_native')
    if part=='target':raw=raw[:-1]+bytes([raw[-1]^1])
    elif part=='native_code':
        # Keep the declared target hash unchanged: caller bytes cannot replace the admitted target.
        raw=raw[:512+0x29a]+bytes([raw[512+0x29a]^1])+raw[512+0x29b:]
    elif part=='root_ir':root.pcode_ir['operations'][0]['sequence']['time']+=1
    elif part=='root_high':root.high_parameter_observation['parameters'][0]['name']='changed'
    elif part=='root_id':root.function_id='0'*64+'!ram:1'
    else:language['ia.sinc']=language['ia.sinc'].replace(b'RSP',b'ESP')
    import aether_re.frame_program as builder
    monkeypatch.setattr(builder,'build_frame_program',lambda *a,**k:pytest.fail('model emission started'))
    with pytest.raises(ValueError):
        result.select_observed_frame_program('root_native',target_bytes=raw,language_sources=language,object_bytes=16)


def test_unsupported_observed_profile_keeps_actual_export_inventory():
    from types import SimpleNamespace
    from aether_re.universal_frame import build_observed_frame_case
    exported=SimpleNamespace(target_sha256='a'*64,total_functions=7,status='complete',worker_execution={'mode':'fixture'})
    packet={'receipt':{'scope':'unit byte input'}}
    result=build_observed_frame_case(exported,target_sha256='a'*64,selector='unused',inputs=packet,object_bytes=16,profile='native-elf')
    assert result['status']=='unsupported_profile' and result['attempted_programs']==0 and result['program'] is None
    assert result['exported_total_functions']==7 and result['backend_status']=='complete'


def test_observed_case_records_available_export_custody_even_without_supported_model():
    from types import SimpleNamespace
    from aether_re.universal_frame import build_observed_frame_case
    exported=SimpleNamespace(target_sha256='a'*64,total_functions=7,status='complete',worker_execution={'mode':'fixture'},
        artifact_dir='unit-worker',artifact_hashes={'unit.json':'b'*64})
    result=build_observed_frame_case(exported,target_sha256='a'*64,selector='unused',inputs={'receipt':{}},object_bytes=16,profile='native-elf')
    assert result['export_artifact_dir']=='unit-worker' and result['export_artifact_hashes']=={'unit.json':'b'*64}
    assert result['attempted_programs']==0
