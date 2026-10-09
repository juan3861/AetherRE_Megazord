import hashlib,pytest
import aether_re.static_worker as static_worker
from aether_re.static_worker import StaticWorkerSpec,probe_static_worker,run_static_worker
def test_worker_hash_race_rejected(tmp_path):
 exe=tmp_path/'fake.exe';exe.write_bytes(b'one');spec=StaticWorkerSpec('fake',exe,hashlib.sha256(b'one').hexdigest(),'v','MIT',1,64,1,1024);exe.write_bytes(b'two')
 with pytest.raises(ValueError,match='worker_executable_hash_mismatch'):run_static_worker(spec,(),tmp_path/'input',tmp_path/'out')

def test_probe_uses_worker_specific_version_arguments(tmp_path,monkeypatch):
 exe=tmp_path/'rizin.exe';exe.write_bytes(b'pinned');observed=[]
 monkeypatch.setattr(static_worker,'_run_bounded',lambda command,**kwargs: observed.append(command) or {'returncode':0,'stdout':'rizin 0.9.1','stderr':'','timed_out':False})
 spec=StaticWorkerSpec('rizin',exe,hashlib.sha256(b'pinned').hexdigest(),'0.9.1','LGPL-3.0-only',10,64,1,1024,('-v',))
 assert probe_static_worker(spec).available
 assert observed==[[str(exe.resolve()),'-v']]
