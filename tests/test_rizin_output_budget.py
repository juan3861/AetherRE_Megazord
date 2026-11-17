from pathlib import Path
from aether_re.adapters.rizin import RizinAdapter

def test_rizin_output_limit_prevents_success(monkeypatch,tmp_path):
 adapter=RizinAdapter(); monkeypatch.setattr(adapter,'_bin',lambda:'worker.exe')
 calls={}
 def bounded(*args, **kwargs):
  calls.update(kwargs)
  return {'stdout':'x'*adapter._MAX_OUTPUT_BYTES,'stderr':'','returncode':-1,'timed_out':False,'resource_exceeded':True,'resource_kind':'output','output_limit_exceeded':True,'output_bytes':adapter._MAX_OUTPUT_BYTES+4096,'captured_output_bytes':adapter._MAX_OUTPUT_BYTES}
 monkeypatch.setattr('aether_re.adapters.rizin.run_bounded',bounded)
 result=adapter.analyze(Path('input'),tmp_path)
 assert result['ok'] is False and result['partial'] is True and result['output_limit_exceeded'] is True
 assert calls.get('output_limit_bytes') == adapter._MAX_OUTPUT_BYTES
 assert result['output_bytes'] == adapter._MAX_OUTPUT_BYTES+4096
 assert b'output truncated' in (tmp_path/'rizin_raw.txt').read_bytes()
