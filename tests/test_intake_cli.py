import json
from argparse import Namespace
from pathlib import Path
from megazord import cmd_intake
def test_intake_requires_auth(tmp_path: Path):
 s=tmp_path/'x.bin'; s.write_bytes(b'abc'); out=tmp_path/'result.json'
 c=cmd_intake(Namespace(source=str(s),case_dir=str(tmp_path/'case'),authorization=str(tmp_path/'missing.json'),result=str(out),no_expand_archives=False,max_files=10,max_total_bytes=100,max_file_bytes=100,max_archive_depth=1,max_compression_ratio=20,max_path_length=128))
 assert c==2 and json.loads(out.read_text())['error']=='authorization_unreadable'