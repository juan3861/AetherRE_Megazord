from pathlib import Path
import json
import pytest
import aether_re.evidence_store as store_module
from aether_re.intake import IntakeRejected, IntakeRequest, prepare_case
from aether_re.kernel_contracts import AuthorizationPolicy, IntakeLimits
from aether_re.evidence_journal import EvidenceJournal, JournalCorruption
P=AuthorizationPolicy.from_dict({'schema':'authorization-policy.v1','basis':'owner','principal':'test','scope':['static-analysis']})
def test_disk_failure_has_no_success_event(tmp_path: Path, monkeypatch):
 s=tmp_path/'x'; s.write_bytes(b'evidence')
 def full(handle): raise OSError('disk_full')
 monkeypatch.setattr(store_module,'_fsync_file',full)
 with pytest.raises(IntakeRejected): prepare_case(IntakeRequest(s,tmp_path/'case',P,IntakeLimits()))
 objects=list((tmp_path/'case'/'objects').rglob('*')) if (tmp_path/'case'/'objects').exists() else []
 assert not [p for p in objects if p.is_file()]
 events=[json.loads(x)['kind'] for x in (tmp_path/'case'/'journal.jsonl').read_text().splitlines()]
 assert 'artifact.published' not in events
def test_interior_corruption_not_tail(tmp_path: Path):
 j=EvidenceJournal.open(tmp_path/'case'); j.append('one',{'n':1}); j.append('two',{'n':2}); j.path.write_bytes(j.path.read_bytes().replace(b'"n":1',b'"n":9'))
 with pytest.raises(JournalCorruption): j.recover_interrupted_tail()