"""Reconstruction behavior: losing width, polarity or parallel phi must fail."""
import runpy
from pathlib import Path

from aether_re.ghidra_pcode_c import reconstruct_high_pcode

fixtures=runpy.run_path(str(Path(__file__).with_name('test_ghidra_pcode_ir.py')))


def parallel_loop_ir():
    """Three loop phis: (a,b) swap while a counter advances."""
    var=fixtures['variable'];op=fixtures['operation'];address=fixtures['ADDRESS']
    data=fixtures['scalar_ir']()
    data['varnodes']=[var('x','register',input=True),var('y','register',input=True),
        var('zero','constant'),var('one','constant',offset='1'),var('three','constant',offset='3'),
        var('ten','constant',offset='a'),var('ret','constant',8),var('i',definition='pi'),
        var('a',definition='pa'),var('b',definition='pb'),var('cond',size=1,definition='cmp'),
        var('next',definition='inc'),var('scaled',definition='mul'),var('out',definition='sum')]
    data['operations']=[op('j','BRANCH',['zero']),
        op('pi','MULTIEQUAL',['zero','next'],'i',pc='ram:401010',phi_predecessors=['b0','b2']),
        op('pa','MULTIEQUAL',['x','b'],'a',pc='ram:401010',time=1,phi_predecessors=['b0','b2']),
        op('pb','MULTIEQUAL',['y','a'],'b',pc='ram:401010',time=2,phi_predecessors=['b0','b2']),
        op('cmp','INT_LESS',['i','three'],'cond',pc='ram:401010',time=3),
        op('branch','CBRANCH',['zero','cond'],pc='ram:401010',time=4),
        op('inc','INT_ADD',['i','one'],'next',pc='ram:401020'),
        op('back','BRANCH',['zero'],pc='ram:401020',time=1),
        op('mul','INT_MULT',['a','ten'],'scaled',pc='ram:401030'),
        op('sum','INT_ADD',['scaled','b'],'out',pc='ram:401030',time=1),
        op('return','RETURN',['ret','out'],pc='ram:401030',time=2)]
    data['blocks']=[
        dict(id='b0',start=address,stop=address,predecessors=[],successors=[dict(block='b1',target_slot=0)],operations=['j']),
        dict(id='b1',start='ram:401010',stop='ram:401017',predecessors=[dict(block='b0',source_slot=0),dict(block='b2',source_slot=0)],
            successors=[dict(block='b3',target_slot=0),dict(block='b2',target_slot=0)],operations=['pi','pa','pb','cmp','branch'],false_out='b3',true_out='b2'),
        dict(id='b2',start='ram:401020',stop='ram:401027',predecessors=[dict(block='b1',source_slot=1)],successors=[dict(block='b1',target_slot=1)],operations=['inc','back']),
        dict(id='b3',start='ram:401030',stop='ram:401037',predecessors=[dict(block='b1',source_slot=0)],successors=[],operations=['mul','sum','return'])]
    return data


def recover(data,**kwargs):
    return reconstruct_high_pcode(data,expected_target=fixtures['TARGET'],expected_address=fixtures['ADDRESS'],
        evidence_sha256=fixtures['EVIDENCE'],**kwargs)


def test_scalar_ir_is_connected_to_existing_ctree_with_explicit_widths():
    report=recover(fixtures['scalar_ir']())
    assert report['status']=='complete',report
    assert report['ctree']['status']=='complete'
    assert report['return_bits']==32
    assert [item['varnode'] for item in report['input_bindings']]==['v0','v1']
    assert '4294967295ULL' in report['structured_c_source']
    assert report['binary_equivalence_proved'] is False
    assert report['original_source_recovered'] is False


def test_phi_is_lowered_to_parallel_edge_copies_and_uses_real_ctree():
    report=recover(fixtures['phi_ir']())
    assert report['status']=='complete',report
    assert len(report['phi_edges'])==2
    assert all(item['copies']==1 for item in report['phi_edges'])
    assert report['ctree']['c_syntax_checked']
    assert len(report['ctree']['emitted_blocks'])==6


def test_loop_phi_snapshots_all_sources_before_any_destination_assignment():
    report=recover(parallel_loop_ir())
    assert report['status']=='complete',report
    assert len(report['phi_edges'])==2
    assert all(item['copies']==3 for item in report['phi_edges'])
    assert report['ctree']['natural_loops_detected']==1


def test_effectful_and_unknown_functions_abstain_without_partial_source():
    for opcode in ('CALLIND','FUTURE_OPERATION','INT_DIV'):
        data=fixtures['scalar_ir']();data['operations'][0]['opcode']=opcode
        if opcode=='CALLIND':
            data['varnodes'].append(fixtures['variable']('fn','register',8,offset='18',input=True))
            data['operations'][0]['inputs']=['fn','v0']
        report=recover(data)
        assert report['status']=='unsupported',report
        assert report['structured_c_source'] is None
        assert any(opcode in error for error in report['errors'])


def test_identity_partial_width_and_unresolved_inputs_never_publish_c():
    for mutation in ('identity','partial','width','input','halt'):
        data=fixtures['scalar_ir']()
        if mutation=='identity':data['target_sha256']='c'*64
        if mutation=='partial':data['complete']=False
        if mutation=='width':
            for variable in data['varnodes'][:3]:variable['size']=16
        if mutation=='input':data['varnodes'][0]['input']=False
        if mutation=='halt':data['varnodes'][3]['offset']='1'
        report=recover(data)
        assert report['status'] in ('invalid','unsupported'),report
        assert report['structured_c_source'] is None


def test_universal_native_worker_uses_intake_snapshot_and_keeps_certification_abstained(tmp_path,monkeypatch):
    from dataclasses import replace
    from aether_re.pipeline import CasePolicy,run_universal_case
    import aether_re.ghidra_headless_bridge as module
    from aether_re.ghidra_headless_bridge import GhidraDecompilationResult,GhidraFunctionInfo
    from aether_re.ghidra_pcode_ir import analyze_high_pcode
    import hashlib,json
    target=tmp_path/'owned.exe';raw=bytearray(256);raw[:2]=b'MZ';raw[60:64]=(128).to_bytes(4,'little');raw[128:132]=b'PE\0\0';target.write_bytes(raw)
    digest=hashlib.sha256(raw).hexdigest();seen=[]
    data=fixtures['scalar_ir']();data['target_sha256']=digest
    projected=analyze_high_pcode(data,expected_target=digest,expected_address=fixtures['ADDRESS'],evidence_sha256=fixtures['EVIDENCE'])
    info=GhidraFunctionInfo('owned','ram:401000',True,2,'int',function_id=digest+'!ram:401000',pcode_ir=data,ir_analysis=projected['summary'],normalized_ir=projected['graph'])
    result=GhidraDecompilationResult(str(target),True,1,1,{info.function_id:info},'','',0,target_sha256=digest,status='complete')
    class Bridge:
        def decompile_binary(self,path,**kwargs):
            seen.append(Path(path));assert Path(path)!=target and hashlib.sha256(Path(path).read_bytes()).hexdigest()==digest
            return result
    monkeypatch.setattr(module,'GhidraHeadlessBridge',Bridge)
    out=tmp_path/'case';policy=replace(CasePolicy.static_only(),request_native_reconstruction=True)
    report=run_universal_case(target,out,policy).to_dict()
    assert seen and report['certification_status']=='abstained' and report['dynamic_status']=='not_requested'
    native=report['native_reconstruction']
    assert native['reconstructed_functions']==native['attempted_functions']==native['total_functions']==1
    assert native['functions'][info.function_id]['reconstruction']['status']=='complete'
    assert native['functions'][info.function_id]['graph']['schema']=='ir.v1'
    assert (out/'native_reconstruction.json').is_file()
    assert json.loads((out/'case_report.json').read_text(encoding='utf-8'))['native_reconstruction']==native
    def over_budget(selector):
        raise ValueError('ghidra_ir_selection_output_budget')
    result.select_reconstruction=over_budget
    out2=tmp_path/'case-over-budget'
    partial=run_universal_case(target,out2,policy).to_dict()['native_reconstruction']
    assert partial['status']=='partial'
    assert partial['attempted_functions']==1 and partial['reconstructed_functions']==0
    assert partial['functions'][info.function_id]['reconstruction']['errors']==['ghidra_ir_selection_output_budget']
    assert (out2/'case_report.json').is_file()
    import aether_re.pipeline as pipeline
    original=result.select_reconstruction
    # Restore a valid selector; make its admitted report exceed the configured
    # envelope budget by one byte, including indentation and dictionary keys.
    del result.select_reconstruction
    cap=(out/'native_reconstruction.json').stat().st_size-1
    monkeypatch.setattr(pipeline,'MAX_NATIVE_REPORT_BYTES',cap,raising=False)
    out3=tmp_path/'case-final-byte-budget'
    bounded=run_universal_case(target,out3,policy).to_dict()['native_reconstruction']
    assert bounded['truncated'] and bounded['attempted_functions']==0
    assert (out3/'native_reconstruction.json').stat().st_size<=cap


def test_changed_ir_after_export_is_rejected_before_reconstruction(monkeypatch):
    context=runpy.run_path(str(Path(__file__).with_name('test_ghidra_interface_contract.py')))
    _,identity=context['fake_export'](monkeypatch,with_ir=True)
    from aether_re.ghidra_headless_bridge import GhidraHeadlessBridge
    result=GhidraHeadlessBridge().decompile_binary('owned.dll')
    result.functions[identity].pcode_ir['operations'][0]['opcode']='INT_SUB'
    import pytest
    with pytest.raises(ValueError,match='ir_changed'):result.select_reconstruction(identity)


def test_nested_mutation_and_input_reordering_cannot_reuse_export_binding(monkeypatch):
    import pytest
    context=runpy.run_path(str(Path(__file__).with_name('test_ghidra_interface_contract.py')))
    for kind in ('pc','context','order'):
        _,identity=context['fake_export'](monkeypatch,with_ir=True)
        from aether_re.ghidra_headless_bridge import GhidraHeadlessBridge
        result=GhidraHeadlessBridge().decompile_binary('owned.dll');data=result.functions[identity].pcode_ir
        if kind=='pc':data['operations'][0]['sequence']['pc']='ram:999999'
        if kind=='context':data['context']['language_id']='forged'
        if kind=='order':data['varnodes'][:2]=reversed(data['varnodes'][:2])
        with pytest.raises(ValueError,match='ir_changed'):result.select_reconstruction(identity)
