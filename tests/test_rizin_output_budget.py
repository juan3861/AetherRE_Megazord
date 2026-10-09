from pathlib import Path
from aether_re.adapters.rizin import RizinAdapter

def test_rizin_output_limit_prevents_success(monkeypatch,tmp_path):
 adapter=RizinAdapter(); monkeypatch.setattr(adapter,'_bin',lambda:'worker.exe')
 monkeypatch.setattr('aether_re.adapters.rizin.run_bounded',lambda *a,**k:{'stdout':'x'*(adapter._MAX_OUTPUT_BYTES+1),'stderr':'','returncode':0,'timed_out':False,'resource_exceeded':False})
 result=adapter.analyze(Path('input'),tmp_path)
 assert result['ok'] is False and result['partial'] is True and result['output_limit_exceeded'] is True
 assert b'output truncated' in (tmp_path/'rizin_raw.txt').read_bytes()
