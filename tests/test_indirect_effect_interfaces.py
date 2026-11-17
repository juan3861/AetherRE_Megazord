"""Optional effect observations do not admit unsupported INDIRECT semantics."""
import copy,json,runpy
from pathlib import Path
import pytest
from aether_re.ghidra_headless_bridge import _load_export,GhidraDecompilationResult
F=runpy.run_path(str(Path(__file__).with_name('test_indirect_effects.py')))
DATA=F['DATA']
def load(tmp_path,observation=True,ir=True):
 (tmp_path/'functions').mkdir();(tmp_path/'functions/f.c').write_text('int owned(void){return 0;}')
 row=dict(name='owned_pair_caller',address=DATA['function_address'],params=2,return_type='ulonglong',signature_source='ANALYSIS',signature='ulonglong owned(ulonglong,ulonglong)',success=True,source_file='functions/f.c')
 if ir:
  (tmp_path/'ir').mkdir();(tmp_path/'ir/f.json').write_text(json.dumps(DATA,sort_keys=True));row['ir_file']='ir/f.json'
 if observation is not False:row['indirect_effect_observation']=F['observation']() if observation is True else observation
 summary=dict(schema='aetherre-ghidra-export.v2',target_sha256=DATA['target_sha256'],complete=True,total_functions=1,decompiled_functions=1,failed_functions=0,
  type_policy=dict(mode='observed_program_types',external_types_injected=False,legacy_type_injection_requested=False),functions=[row])
 (tmp_path/'decompilation_summary.json').write_text(json.dumps(summary))
 functions,*_= _load_export(tmp_path,DATA['target_sha256'])
 return GhidraDecompilationResult('never-executed',True,1,1,functions,'','',0,target_sha256=DATA['target_sha256'])
def test_loader_preserves_optional_observation_and_selected_refusal(tmp_path):
 result=load(tmp_path);info=next(iter(result.functions.values()))
 assert info.indirect_effect_observation==F['observation']()
 selected=result.select_reconstruction(info.function_id)
 assert selected['status']=='unsupported'
 assert selected['indirect_effect_observation']==F['observation']()
 assert info.ir_preview()['indirect_effects']==dict(total=4,resolved=4,unresolved=0,complete=True,alias_semantics_proved=False)
def test_old_export_without_sidecar_stays_absent(tmp_path):
 result=load(tmp_path,False);info=next(iter(result.functions.values()))
 assert info.indirect_effect_observation is None
 assert 'indirect_effect_observation' not in result.select_reconstruction(info.function_id)
 assert 'indirect_effects' not in info.ir_preview()
def test_sidecar_requires_ir(tmp_path):
 with pytest.raises(ValueError,match='indirect_effect_observation_without_ir'):load(tmp_path,ir=False)
def test_forged_raw_ir_hash_is_rejected_at_intake(tmp_path):
 observed=F['observation']();observed['source_ir_sha256']='0'*64
 with pytest.raises(ValueError,match='indirect_effect_observation_invalid'):load(tmp_path,observed)
@pytest.mark.parametrize('consumer',['selection','preview'])
def test_post_admission_observation_change_is_rejected(tmp_path,consumer):
 result=load(tmp_path);info=next(iter(result.functions.values()))
 info.indirect_effect_observation['entries'][0]['effect']['sequence']['time']=0
 with pytest.raises(ValueError,match='indirect_effect_observation_changed'):
  result.select_reconstruction(info.function_id) if consumer=='selection' else info.ir_preview()
def test_post_admission_insertion_is_not_a_producer_observation(tmp_path):
 result=load(tmp_path,False);info=next(iter(result.functions.values()))
 info.indirect_effect_observation=F['observation']()
 with pytest.raises(ValueError,match='indirect_effect_observation_changed'):info.ir_preview()
