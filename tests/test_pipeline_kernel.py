import json
from pathlib import Path
from aether_re.pipeline import run_megazord
def test_pipeline_kernel(tmp_path: Path):
 t=tmp_path/'sample.bin'; t.write_bytes(b'MZ'+b'\0'*126)
 r=run_megazord(t,out_dir=tmp_path/'run',use_adapters=False,deep=False)
 m=json.loads((tmp_path/'run'/'intake'/'manifest.json').read_text())
 assert r.case_id==m['case_id'] and r.root_artifact_id==m['root_artifact']['artifact_id'] and Path(r.evidence_journal).is_file()
 snapshot = tmp_path/'run'/'input.snapshot'
 assert snapshot.read_bytes() == t.read_bytes()
 assert snapshot.stat().st_nlink == 1
