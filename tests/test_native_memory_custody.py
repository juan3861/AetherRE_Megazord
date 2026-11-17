import hashlib,json,runpy
from pathlib import Path
import pytest
from aether_re.intake import IntakeRequest,prepare_case
from aether_re.kernel_contracts import AuthorizationPolicy,IntakeLimits
from aether_re.native_memory_custody import publish_memory_derivation,verify_memory_derivation,replay_memory_derivation

def case(tmp_path,profile='pe'):
    name='test_pe_memory_map.py' if profile=='pe' else 'test_elf_memory_map.py'
    fixtures=runpy.run_path(str(Path(__file__).with_name(name)))
    data=fixtures['fixture']() if profile=='pe' else fixtures['fixture'](dynamic=True)
    source=tmp_path/'source.bin';source.write_bytes(data)
    auth=AuthorizationPolicy.from_dict(dict(schema='authorization-policy.v1',basis='owner',principal='local-owner',scope=['static-analysis']))
    admitted=prepare_case(IntakeRequest(source,tmp_path/'input',auth,IntakeLimits(),False))
    return admitted.manifest_path.parent

@pytest.mark.parametrize('profile,sparse',[('pe',False),('elf',False),('elf',True)])
def test_published_derivation_is_bound_and_replayable_without_mutating_parent(tmp_path,profile,sparse):
    parent=case(tmp_path,profile)
    before={n:(parent/n).read_bytes() for n in ('manifest.json','journal.jsonl','custody-receipt.json')}
    result=publish_memory_derivation(parent,tmp_path/'derived',profile=profile,space_id=0,sparse=sparse)
    assert result['status']=='complete' and result['process_snapshot_proved'] is False
    assert verify_memory_derivation(tmp_path/'derived')['status']=='pass'
    replay=replay_memory_derivation(tmp_path/'derived',tmp_path/'replay')
    assert replay['status']=='complete' and replay['report']['sha256']==result['report']['sha256']
    assert before=={n:(parent/n).read_bytes() for n in before}

def test_existing_destination_and_parent_overlap_are_refused(tmp_path):
    parent=case(tmp_path);dest=tmp_path/'derived';dest.mkdir()
    with pytest.raises((ValueError,FileExistsError)):publish_memory_derivation(parent,dest,profile='pe',space_id=0)
    with pytest.raises(ValueError):publish_memory_derivation(parent,parent/'derived',profile='pe',space_id=0)

def test_parent_manifest_and_object_tampering_are_refused_before_publication(tmp_path):
    parent=case(tmp_path)
    manifest=parent/'manifest.json';original=manifest.read_bytes();manifest.write_bytes(original+b' ')
    with pytest.raises(ValueError):publish_memory_derivation(parent,tmp_path/'derived',profile='pe',space_id=0)
    assert not (tmp_path/'derived').exists()
    manifest.write_bytes(original);root=json.loads(original)['root_artifact'];target=parent/root['object_path'];target.write_bytes(b'bad')
    with pytest.raises(ValueError):publish_memory_derivation(parent,tmp_path/'derived',profile='pe',space_id=0)

def test_mutated_product_fails_verification(tmp_path):
    parent=case(tmp_path);result=publish_memory_derivation(parent,tmp_path/'derived',profile='pe',space_id=0)
    product=tmp_path/'derived'/result['report']['object_path'];product.write_bytes(b'{}')
    assert verify_memory_derivation(tmp_path/'derived')['status']=='fail'
    with pytest.raises(ValueError):replay_memory_derivation(tmp_path/'derived',tmp_path/'replay')

@pytest.mark.parametrize('options',[dict(profile='unknown',space_id=0),dict(profile='pe',space_id=True),dict(profile='pe',space_id=0,sparse=True)])
def test_invalid_options_do_not_create_output(tmp_path,options):
    parent=case(tmp_path)
    with pytest.raises(ValueError):publish_memory_derivation(parent,tmp_path/'derived',**options)
    assert not (tmp_path/'derived').exists()

def test_partial_publication_never_becomes_complete(tmp_path,monkeypatch):
    from aether_re.evidence_store import EvidenceStore
    parent=case(tmp_path);original=EvidenceStore.publish_file;calls=[]
    def interrupted(self,*args,**kwargs):
        calls.append(1)
        if len(calls)==3:raise OSError('injected publication failure')
        return original(self,*args,**kwargs)
    monkeypatch.setattr(EvidenceStore,'publish_file',interrupted)
    with pytest.raises(OSError):publish_memory_derivation(parent,tmp_path/'derived',profile='pe',space_id=0)
    assert not (tmp_path/'derived/manifest.json').exists()
    assert verify_memory_derivation(tmp_path/'derived')['status']=='fail'
    assert json.loads((tmp_path/'derived/journal.jsonl').read_text().splitlines()[-1])['kind']=='derivation.failed'

def test_disk_reserve_refuses_output_before_publication(tmp_path,monkeypatch):
    from types import SimpleNamespace
    import aether_re.native_memory_custody as custody
    parent=case(tmp_path);monkeypatch.setattr(custody.shutil,'disk_usage',lambda _:SimpleNamespace(free=0))
    with pytest.raises(ValueError,match='reserve'):publish_memory_derivation(parent,tmp_path/'derived',profile='pe',space_id=0)
    assert not (tmp_path/'derived').exists()

def test_journal_budget_is_checked_before_hashing_custody(tmp_path,monkeypatch):
    import aether_re.native_memory_custody as custody
    parent=case(tmp_path)
    with (parent/'journal.jsonl').open('r+b') as handle:handle.truncate(2*1024*1024+1)
    monkeypatch.setattr(custody,'verify_custody_receipt',lambda *a,**k:pytest.fail('oversized journal reached custody hash'))
    with pytest.raises(ValueError,match='budget'):publish_memory_derivation(parent,tmp_path/'derived',profile='pe',space_id=0)
    assert not (tmp_path/'derived').exists()

def test_context_binding_rejects_cross_target_space_base_width_and_endian(tmp_path):
    from aether_re.native_memory_custody import bind_memory_derivation
    parent=case(tmp_path);result=publish_memory_derivation(parent,tmp_path/'derived',profile='pe',space_id=0)
    digest=json.loads((parent/'manifest.json').read_text())['root_artifact']['sha256']
    context=dict(target_sha256=digest,space_id=0,image_base=0x140000000,bits=64,endian='little')
    bound=bind_memory_derivation(tmp_path/'derived',**context)
    assert bound['status']=='bound' and bound['report']['sha256']==result['report']['sha256']
    for change in (dict(target_sha256='0'*64),dict(space_id=1),dict(image_base=0),dict(bits=32),dict(endian='big'),dict(space_id=True)):
        with pytest.raises(ValueError):bind_memory_derivation(tmp_path/'derived',**{**context,**change})

def test_declared_analysis_base_is_custodied_recomputed_and_replayed(tmp_path):
    from aether_re.native_memory_custody import admit_memory_context
    parent=case(tmp_path,'elf')
    result=publish_memory_derivation(parent,tmp_path/'derived',profile='elf',space_id=433,sparse=True,analysis_base=0x100000)
    assert verify_memory_derivation(tmp_path/'derived')['status']=='pass'
    assert replay_memory_derivation(tmp_path/'derived',tmp_path/'replay')['report']['sha256']==result['report']['sha256']
    digest=json.loads((parent/'manifest.json').read_text())['root_artifact']['sha256']
    bound=admit_memory_context(tmp_path/'derived').bind(target_sha256=digest,space_id=433,image_base=0x100000,bits=64,endian='little')
    assert bound['context']['analysis_addressing']['link_base']==0x400000
    assert bound['context']['analysis_addressing']['bias']==-0x300000
