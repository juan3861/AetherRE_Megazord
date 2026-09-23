import hashlib,pytest
from aether_re.static_worker import StaticWorkerSpec,run_static_worker
def test_worker_hash_race_rejected(tmp_path):
 exe=tmp_path/'fake.exe';exe.write_bytes(b'one');spec=StaticWorkerSpec('fake',exe,hashlib.sha256(b'one').hexdigest(),'v','MIT',1,64,1,1024);exe.write_bytes(b'two')
 with pytest.raises(ValueError,match='worker_executable_hash_mismatch'):run_static_worker(spec,(),tmp_path/'input',tmp_path/'out')
