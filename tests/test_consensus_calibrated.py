from aether_re.engines.consensus import merge_function_evidence
from aether_re.models import FunctionEvidence
def test_calibration_beats_majority_and_spaces_do_not_merge():
 x=lambda s,n,space='elf:vaddr':FunctionEvidence('0x1000',n,s,.9,.8,address_space=space,evidence_refs=['ev:'+s])
 m=merge_function_evidence([x('ghidra','safe'),x('rizin','wrong'),x('retdec','wrong')],reliability={'ghidra':.95,'rizin':.55,'retdec':.5})
 assert m[0].name=='safe' and m[0].conflicts
 assert len(merge_function_evidence([x('ilspy','M','dotnet:il'),x('ghidra','M','pe:rva')]))==2
