import zipfile
from dataclasses import replace
import pytest
from aether_re.ir import *
from aether_re.kernel_contracts import EpistemicState
def test_identity_and_graph():
 n=IRNode('function','x',IRLocation('pe:rva','0x1'),'fixture',('ev:x',),EpistemicState.EXACT,1.,(),{})
 assert n.identity != replace(n,location=IRLocation('dotnet:il','0x1')).identity
 with pytest.raises(ValueError,match='ir_evidence_refs_required'):validate_ir(IRDocument('ir.v1','sha256:x','native-pe',(replace(n,evidence_refs=()),),(),()))
