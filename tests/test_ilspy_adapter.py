from aether_re.adapters.ilspy import ILSpyAdapter

def test_ilspy_adapter_fails_closed_when_pinned_tools_missing(tmp_path):
 adapter=ILSpyAdapter(dotnet=str(tmp_path/'dotnet.exe'),ilspycmd=str(tmp_path/'ilspycmd.dll'))
 assert adapter.available() is False
 assert adapter.analyze(tmp_path/'x.dll',tmp_path/'out')['error']=='ilspycmd_worker_unavailable_or_hash_mismatch'
