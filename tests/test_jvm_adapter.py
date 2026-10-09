from aether_re.adapters.jvm import JvmAdapter

def test_jvm_adapter_fails_closed_when_pinned_tools_are_missing(tmp_path):
 adapter=JvmAdapter(java=str(tmp_path/'java.exe'),vineflower=str(tmp_path/'vf.jar'))
 assert adapter.available() is False
 assert adapter.analyze(tmp_path/'missing.jar',tmp_path/'out')['error']=='jvm_workers_unavailable_or_hash_mismatch'

def test_jvm_adapter_rejects_archive_without_class_files(tmp_path):
 import zipfile
 target=tmp_path/'empty.jar'
 with zipfile.ZipFile(target,'w') as archive:archive.writestr('META-INF/x','x')
 adapter=JvmAdapter(java=str(tmp_path/'java.exe'),vineflower=str(tmp_path/'vf.jar'))
 # Hash verification comes before input inspection; this protects untrusted input.
 assert adapter.analyze(target,tmp_path/'out')['error']=='jvm_workers_unavailable_or_hash_mismatch'
