from pathlib import Path
from aether_re.intake import IntakeRequest, prepare_case, replay_case
from aether_re.kernel_contracts import AuthorizationPolicy, IntakeLimits
P=AuthorizationPolicy.from_dict({'schema':'authorization-policy.v1','basis':'owner','principal':'test','scope':['static-analysis']})
def test_replay_verifies_hashes(tmp_path: Path):
 s=tmp_path/'x'; s.write_bytes(b'\0asm\x01\0\0\0'); first=prepare_case(IntakeRequest(s,tmp_path/'first',P,IntakeLimits())); r=replay_case(first.manifest_path,tmp_path/'replay'); assert r.status=='pass' and r.root_sha256==first.root_artifact.sha256 and r.journal_verification.status=='pass'