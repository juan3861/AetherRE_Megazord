import hashlib,json
from aether_re.jar_worker import verify_jar_workers_lock

def test_jar_worker_lock_rehashes_runtime_and_archive(tmp_path):
 java=tmp_path/'java.exe';jar=tmp_path/'tool.jar';java.write_bytes(b'java');jar.write_bytes(b'jar')
 lock={'schema':'jar-workers-lock.v1','policy':{},'workers':[{'name':'x','version':'1.0.0','license_spdx':'MIT','profiles':['jvm'],'official_url':'https://example.test/x','java_executable':str(java),'java_sha256':hashlib.sha256(b'java').hexdigest(),'archive':str(jar),'archive_sha256':hashlib.sha256(b'jar').hexdigest(),'version_argv':['--version']}]}
 path=tmp_path/'lock.json';path.write_text(json.dumps(lock))
 assert verify_jar_workers_lock(path)['verified'] is True
 jar.write_bytes(b'tampered')
 assert verify_jar_workers_lock(path)['workers'][0]['state']=='archive_hash_mismatch'
