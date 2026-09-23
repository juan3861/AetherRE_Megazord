from pathlib import Path
import pytest
from aether_re.evidence_store import EvidenceStore, PublicationError
from aether_re.kernel_contracts import AuthorizationPolicy
P=AuthorizationPolicy.from_dict({'schema':'authorization-policy.v1','basis':'owner','principal':'test','scope':['static-analysis']})
def test_store_publish_and_verify(tmp_path: Path):
 source=tmp_path/'a'; source.write_bytes(b'abc'); s=EvidenceStore(tmp_path/'case'); a=s.publish_file(source,media_type='application/octet-stream',origin='a',authorization=P,max_bytes=8); assert s.resolve(a).read_bytes()==b'abc'; s.verify(a)
def test_store_budget(tmp_path: Path):
 source=tmp_path/'a'; source.write_bytes(b'abc');
 with pytest.raises(PublicationError,match='source_size_budget_exceeded'): EvidenceStore(tmp_path/'case').publish_file(source,media_type='x',origin='a',authorization=P,max_bytes=2)