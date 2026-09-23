import json
from pathlib import Path
from aether_re.intake import IntakeRequest, prepare_case, verify_case, replay_case
from aether_re.kernel_contracts import AuthorizationPolicy, IntakeLimits
P=AuthorizationPolicy.from_dict({'schema':'authorization-policy.v1','basis':'owner','principal':'test','scope':['static-analysis']})
def test_file_case_and_replay(tmp_path: Path):
 f=tmp_path/'x'; f.write_bytes(b'abc'); r=prepare_case(IntakeRequest(f,tmp_path/'case',P,IntakeLimits())); assert json.loads(r.manifest_path.read_text())['case_id']==r.case_id; assert verify_case(tmp_path/'case').status=='pass'; assert replay_case(r.manifest_path,tmp_path/'replay').status=='pass'
def test_directory_sorted(tmp_path: Path):
 d=tmp_path/'d'; d.mkdir(); (d/'b').write_bytes(b'b'); (d/'a').write_bytes(b'a'); r=prepare_case(IntakeRequest(d,tmp_path/'case',P,IntakeLimits())); assert [x['relative_path'] for x in r.inventory]==['a','b']