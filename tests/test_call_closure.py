"""Direct call composition requires more than opcode/arity shape matching."""
from copy import deepcopy
import hashlib,json,runpy,struct
from pathlib import Path
import pytest
from aether_re.call_closure import reconstruct_direct_call_closure
from aether_re.ghidra_headless_bridge import GhidraFunctionInfo,GhidraDecompilationResult
from aether_re.ghidra_pcode_ir import analyze_high_pcode

helpers=runpy.run_path(str(Path(__file__).with_name('test_ghidra_pcode_ir.py')))
pe=runpy.run_path(str(Path(__file__).with_name('test_pe_memory_map.py')))
high=runpy.run_path(str(Path(__file__).with_name('test_high_parameters.py')))


def make_export(tmp_path,*,executable=True,quarantine=False):
    image=pe['fixture']();struct.pack_into('<Q',image,152+24,0x400000)
    struct.pack_into('<I',image,152+240+36,0x60000020 if executable else 0x40000040)
    if quarantine:pe['directory'](image,12,0x1100,16)
    binary=tmp_path/'owned-synthetic.dll';binary.write_bytes(image);target=hashlib.sha256(image).hexdigest()
    caller=helpers['scalar_ir']();callee=helpers['scalar_ir']()
    for data,address in ((caller,'ram:401000'),(callee,'ram:401100')):
        data['target_sha256']=target;data['function_address']=address
        data['blocks'][0].update(start=address,stop='ram:'+format(int(address.split(':')[1],16)+7,'x'))
        for op in data['operations']:op['sequence']['pc']=address
    caller['varnodes'].append(helpers['variable']('callee','memory',8,'401100'))
    caller['operations'][0].update(opcode='CALL',inputs=['callee','v0','v1'])
    functions={}
    for name,data in (('caller',caller),('callee',callee)):
        evidence=hashlib.sha256(json.dumps(data,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        analysis=analyze_high_pcode(data,expected_target=target,expected_address=data['function_address'],evidence_sha256=evidence)
        observation=high['high_observation']();observation.update(target_sha256=target,function_address=data['function_address'])
        identity=target+'!'+data['function_address']
        functions[identity]=GhidraFunctionInfo(name,data['function_address'],True,2,'uint',function_id=identity,
            pcode_ir=data,ir_analysis=analysis['summary'],normalized_ir=analysis['graph'],high_parameter_observation=observation)
    return GhidraDecompilationResult(str(binary),True,2,2,functions,'','',0,target_sha256=target,status='complete')


def result(tmp_path,**kwargs):return reconstruct_direct_call_closure(make_export(tmp_path), 'caller', **kwargs)


def test_direct_scalar_calls_generate_one_shared_runtime_and_explicit_hypotheses(tmp_path):
    report=result(tmp_path)
    assert report['status']=='complete',report
    assert report['call_model']['schema']=='bounded-direct-pure-calls.v1'
    assert len(report['call_model']['functions'])==2 and len(report['call_model']['call_sites'])==1
    assert report['structured_c_source'].count('struct aether_sparse_event {')==1
    assert 'aether_call_enter(' in report['structured_c_source']
    assert [p['name'] for p in report['runtime_parameters']]==['aether_memory','aether_calls']
    assert report['abi_recovered'] is report['binary_equivalence_proved'] is report['call_semantics_proved'] is False


def test_default_reconstruction_still_refuses_calls(tmp_path):
    export=make_export(tmp_path)
    assert export.select_reconstruction('caller',memory_model='bounded-bytes.v2')['status']=='unsupported'


def test_nonexecutable_file_regions_are_not_admitted_by_call_shape(tmp_path):
    report=reconstruct_direct_call_closure(make_export(tmp_path,executable=False),'caller')
    assert report['status']=='unsupported' and 'call_closure_executable_mapping' in report['errors']


def test_the_target_file_cannot_change_after_export(tmp_path):
    export=make_export(tmp_path);Path(export.binary_path).write_bytes(b'changed')
    with pytest.raises(ValueError,match='call_closure_target_changed'):
        reconstruct_direct_call_closure(export,'caller')


def test_callee_must_exist_in_the_same_identity_bound_inventory(tmp_path):
    export=make_export(tmp_path);identity=export.get_unique_function('callee').function_id
    del export.functions[identity];export.total_functions=export.decompiled_functions=1
    report=reconstruct_direct_call_closure(export,'caller')
    assert report['status']=='unsupported' and 'call_closure_callee_unavailable' in report['errors']


def test_mutated_callee_payload_is_not_reused_for_composition(tmp_path):
    export=make_export(tmp_path);export.get_unique_function('callee').pcode_ir['varnodes'][0]['offset']='10'
    with pytest.raises(ValueError,match='ghidra_reconstruction_ir_changed'):
        reconstruct_direct_call_closure(export,'caller')


def test_configuration_limits_are_exact_integers(tmp_path):
    with pytest.raises(ValueError,match='call_closure_budget_invalid'):
        result(tmp_path,max_depth=True)


def test_the_complete_closure_is_subject_to_function_quota(tmp_path):
    report=result(tmp_path,max_functions=1)
    assert report['status']=='unsupported' and 'call_closure_function_budget' in report['errors']


def replace_function(export,name,data,observation=None):
    old=export.get_unique_function(name);data=deepcopy(data)
    data['target_sha256']=export.target_sha256;address=data['function_address']
    evidence=hashlib.sha256(json.dumps(data,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    analysis=analyze_high_pcode(data,expected_target=export.target_sha256,expected_address=address,evidence_sha256=evidence)
    observed=deepcopy(observation if observation is not None else old.high_parameter_observation)
    observed.update(target_sha256=export.target_sha256,function_address=address)
    identity=export.target_sha256+'!'+address
    info=GhidraFunctionInfo(name,address,True,len(observed['parameters']),'uint',function_id=identity,
        pcode_ir=data,ir_analysis=analysis['summary'],normalized_ir=analysis['graph'],high_parameter_observation=observed)
    del export.functions[old.function_id];export.functions[identity]=info
    return info


def clone_function(export,name,address,call_target=None):
    original=export.get_unique_function('callee');data=deepcopy(original.pcode_ir)
    data['function_address']=address;data['blocks'][0].update(start=address,stop='ram:'+format(int(address.split(':')[1],16)+7,'x'))
    for op in data['operations']:op['sequence']['pc']=address
    if call_target:
        data['varnodes'].append(helpers['variable']('called','memory',8,call_target.split(':')[1]))
        data['operations'][0].update(opcode='CALL',inputs=['called','v0','v1'])
    observation=deepcopy(original.high_parameter_observation)
    # replace_function owns a name, so install a temporary identity first.
    identity=export.target_sha256+'!'+address
    export.functions[identity]=GhidraFunctionInfo(name,address,True,2,'uint',function_id=identity,high_parameter_observation=observation)
    info=replace_function(export,name,data,observation)
    export.total_functions=export.decompiled_functions=len(export.functions)
    return info


def test_special_return_or_halt_in_callee_is_not_reinterpreted_as_pure_return(tmp_path):
    export=make_export(tmp_path);data=deepcopy(export.get_unique_function('callee').pcode_ir)
    next(v for v in data['varnodes'] if v['id']=='c0')['offset']='1'
    replace_function(export,'callee',data)
    report=reconstruct_direct_call_closure(export,'caller')
    assert report['status']=='unsupported' and any('pcode_c_unmodeled_return_target_or_halt' in e for e in report['errors'])


def test_loader_quarantined_code_bytes_cannot_authorize_a_callee(tmp_path):
    report=reconstruct_direct_call_closure(make_export(tmp_path,quarantine=True),'caller')
    assert report['status']=='unsupported' and 'call_closure_executable_mapping' in report['errors']


def test_zero_fill_is_not_file_backed_executable_body_evidence(tmp_path):
    export=make_export(tmp_path);callee=deepcopy(export.get_unique_function('callee').pcode_ir)
    callee['function_address']='ram:401280';callee['blocks'][0].update(start='ram:401280',stop='ram:401287')
    for op in callee['operations']:op['sequence']['pc']='ram:401280'
    replace_function(export,'callee',callee)
    caller=deepcopy(export.get_unique_function('caller').pcode_ir)
    next(v for v in caller['varnodes'] if v['id']=='callee')['offset']='401280'
    replace_function(export,'caller',caller)
    report=reconstruct_direct_call_closure(export,'caller')
    assert report['status']=='unsupported' and 'call_closure_executable_mapping' in report['errors']


def test_recursive_call_graph_is_refused_in_this_profile(tmp_path):
    export=make_export(tmp_path);callee=deepcopy(export.get_unique_function('callee').pcode_ir)
    callee['varnodes'].append(helpers['variable']('recursive','memory',8,'401000'))
    callee['operations'][0].update(opcode='CALL',inputs=['recursive','v0','v1'])
    replace_function(export,'callee',callee)
    report=reconstruct_direct_call_closure(export,'caller')
    assert report['status']=='unsupported' and 'call_closure_cycle' in report['errors']


def test_callee_observation_cannot_change_after_admission(tmp_path):
    export=make_export(tmp_path);export.get_unique_function('callee').high_parameter_observation['parameters'][0]['name']='changed'
    with pytest.raises(ValueError,match='high_parameter_observation_changed'):
        reconstruct_direct_call_closure(export,'caller')


def test_observed_symbol_width_must_match_the_single_transport_input(tmp_path):
    export=make_export(tmp_path);info=export.get_unique_function('callee');observation=deepcopy(info.high_parameter_observation)
    observation['parameters'][0]['size']=8
    replace_function(export,'callee',info.pcode_ir,observation)
    report=reconstruct_direct_call_closure(export,'caller')
    assert report['status']=='unsupported' and 'call_closure_parameter_width' in report['errors']


def test_inventory_addresses_must_be_canonical_and_unaliased(tmp_path):
    export=make_export(tmp_path);info=export.get_unique_function('callee');del export.functions[info.function_id]
    info.address='ram:00401100';info.function_id=export.target_sha256+'!'+info.address;export.functions[info.function_id]=info
    with pytest.raises(ValueError,match='call_closure_inventory_identity'):
        reconstruct_direct_call_closure(export,'caller')


def test_cached_shared_subtree_still_counts_toward_maximum_call_depth(tmp_path):
    export=make_export(tmp_path)
    # caller first visits callee->leaf at depth two, then mid->mid2->callee->leaf
    # must not reuse the shallow cached visit to hide the depth-four path.
    clone_function(export,'leaf','ram:401140')
    clone_function(export,'mid2','ram:401180',call_target='ram:401100')
    clone_function(export,'mid','ram:401160',call_target='ram:401180')
    callee=deepcopy(export.get_unique_function('callee').pcode_ir)
    callee['varnodes'].append(helpers['variable']('called','memory',8,'401140'))
    callee['operations'][0].update(opcode='CALL',inputs=['called','v0','v1'])
    replace_function(export,'callee',callee)
    caller=deepcopy(export.get_unique_function('caller').pcode_ir)
    caller['varnodes'].extend([helpers['variable']('mid','memory',8,'401160'),helpers['variable']('second',definition='o2')])
    caller['operations'].insert(1,helpers['operation']('o2','CALL',['mid','v0','v1'],'second',time=1))
    caller['operations'][-1]['sequence'].update(time=2,order=2)
    caller['blocks'][0]['operations']=['o0','o2','o1']
    replace_function(export,'caller',caller)
    report=reconstruct_direct_call_closure(export,'caller',max_depth=3)
    assert report['status']=='unsupported' and 'call_closure_depth_budget' in report['errors']


def test_a_forged_backend_context_cannot_enable_call_lowering(tmp_path):
    from aether_re.ghidra_pcode_c import reconstruct_high_pcode
    export=make_export(tmp_path);info=export.get_unique_function('caller')
    report=reconstruct_high_pcode(info.pcode_ir,expected_target=export.target_sha256,expected_address=info.address,
        evidence_sha256=info.ir_analysis['source_ir_sha256'],memory_model='bounded-bytes.v2',_call_context={})
    assert report['status']=='invalid' and report['errors']==['call_closure_context_not_admitted']


def loop_export(tmp_path):
    export=make_export(tmp_path);data=deepcopy(export.get_unique_function('caller').pcode_ir)
    v=helpers['variable'];op=helpers['operation']
    data['varnodes']=[v('v0','register',offset='8',input=True),v('v1','register',offset='10',input=True),
        v('zero','constant',offset='0'),v('one','constant',offset='1'),v('three','constant',offset='3'),v('ret','constant',8),
        v('bound',definition='o0'),v('index',definition='o2'),v('acc',definition='o3'),v('cond',size=1,definition='o4'),
        v('called_value',definition='o6'),v('next',definition='o7'),v('callee','memory',8,'401100'),
        v('to_header','memory',8,'401010'),v('to_body','memory',8,'401020')]
    data['operations']=[op('o0','INT_AND',['v0','three'],'bound'),op('o1','BRANCH',['to_header'],time=1),
        op('o2','MULTIEQUAL',['zero','next'],'index',pc='ram:401010',phi_predecessors=['b0','b2']),
        op('o3','MULTIEQUAL',['v1','called_value'],'acc',pc='ram:401010',time=1,phi_predecessors=['b0','b2']),
        op('o4','INT_LESS',['index','bound'],'cond',pc='ram:401010',time=2),
        op('o5','CBRANCH',['to_body','cond'],pc='ram:401010',time=3),
        op('o6','CALL',['callee','acc','index'],'called_value',pc='ram:401020'),
        op('o7','INT_ADD',['index','one'],'next',pc='ram:401020',time=1),
        op('o8','BRANCH',['to_header'],pc='ram:401020',time=2),
        op('o9','RETURN',['ret','acc'],pc='ram:401030')]
    data['blocks']=[
        dict(id='b0',start='ram:401000',stop='ram:401007',predecessors=[],successors=[dict(block='b1',target_slot=0)],operations=['o0','o1']),
        dict(id='b1',start='ram:401010',stop='ram:401017',predecessors=[dict(block='b0',source_slot=0),dict(block='b2',source_slot=0)],
            successors=[dict(block='b3',target_slot=0),dict(block='b2',target_slot=0)],true_out='b2',false_out='b3',operations=['o2','o3','o4','o5']),
        dict(id='b2',start='ram:401020',stop='ram:401027',predecessors=[dict(block='b1',source_slot=1)],successors=[dict(block='b1',target_slot=1)],operations=['o6','o7','o8']),
        dict(id='b3',start='ram:401030',stop='ram:401037',predecessors=[dict(block='b1',source_slot=0)],successors=[],operations=['o9'])]
    observation=deepcopy(export.get_unique_function('caller').high_parameter_observation)
    observation['parameters'][0]['instances']=dict(available=True,total=1,omitted=0,observed=['v0'])
    replace_function(export,'caller',data,observation)
    return export


def branch_export(tmp_path):
    export=make_export(tmp_path);v=helpers['variable'];op=helpers['operation']
    callee=deepcopy(export.get_unique_function('callee').pcode_ir)
    callee['varnodes'][0],callee['varnodes'][1]=callee['varnodes'][1],callee['varnodes'][0]
    callee['operations'][0]['opcode']='INT_SUB'
    replace_function(export,'callee',callee)
    data=deepcopy(export.get_unique_function('caller').pcode_ir)
    data['varnodes']=[v('v0','register',offset='8',input=True),v('v1','register',offset='10',input=True),
        v('zero','constant'),v('ret','constant',8),v('cond',size=1,definition='o0'),
        v('left',definition='o2'),v('right',definition='o4'),v('callee','memory',8,'401100'),v('to_left','memory',8,'401010')]
    data['operations']=[op('o0','INT_NOTEQUAL',['v0','zero'],'cond'),op('o1','CBRANCH',['to_left','cond'],time=1),
        op('o2','CALL',['callee','v0','v1'],'left',pc='ram:401010'),op('o3','RETURN',['ret','left'],pc='ram:401010',time=1),
        op('o4','CALL',['callee','v1','v0'],'right',pc='ram:401020'),op('o5','RETURN',['ret','right'],pc='ram:401020',time=1)]
    data['blocks']=[
        dict(id='b0',start='ram:401000',stop='ram:401007',predecessors=[],successors=[dict(block='b2',target_slot=0),dict(block='b1',target_slot=0)],true_out='b1',false_out='b2',operations=['o0','o1']),
        dict(id='b1',start='ram:401010',stop='ram:401017',predecessors=[dict(block='b0',source_slot=1)],successors=[],operations=['o2','o3']),
        dict(id='b2',start='ram:401020',stop='ram:401027',predecessors=[dict(block='b0',source_slot=0)],successors=[],operations=['o4','o5'])]
    observation=deepcopy(export.get_unique_function('caller').high_parameter_observation)
    observation['parameters'][0]['instances']=dict(available=True,total=1,omitted=0,observed=['v0'])
    replace_function(export,'caller',data,observation)
    return export


def test_transport_order_uses_verified_mapping_instead_of_varnode_iteration_order(tmp_path):
    report=reconstruct_direct_call_closure(branch_export(tmp_path),'caller')
    assert report['status']=='complete',report
    assert all(s['transport_argument_slots']==[1,0] for s in report['call_model']['call_sites'])


def test_calls_in_a_phi_loop_keep_one_shared_state(tmp_path):
    report=reconstruct_direct_call_closure(loop_export(tmp_path),'caller')
    assert report['status']=='complete',report
    assert report['ctree']['natural_loops_detected']>=1


def test_runtime_context_fingerprint_changes_with_callee_semantics(tmp_path):
    export=make_export(tmp_path);before=reconstruct_direct_call_closure(export,'caller')
    callee=deepcopy(export.get_unique_function('callee').pcode_ir);callee['operations'][0]['opcode']='INT_SUB'
    replace_function(export,'callee',callee);after=reconstruct_direct_call_closure(export,'caller')
    assert before['status']==after['status']=='complete'
    assert before['call_model']['context_sha256']!=after['call_model']['context_sha256']


def test_missing_target_bytes_fail_with_a_defined_admission_error(tmp_path):
    export=make_export(tmp_path);Path(export.binary_path).unlink()
    with pytest.raises(ValueError,match='call_closure_target_unavailable'):
        reconstruct_direct_call_closure(export,'caller')


def test_boolean_inventory_denominator_is_not_an_integer_count(tmp_path):
    export=make_export(tmp_path);del export.functions[export.get_unique_function('callee').function_id]
    export.total_functions=True
    with pytest.raises(ValueError,match='call_closure_inventory_invalid'):
        reconstruct_direct_call_closure(export,'caller')


def test_output_budget_refusal_does_not_retain_a_large_executable_ctree(tmp_path,monkeypatch):
    import aether_re.call_closure as module
    export=make_export(tmp_path);complete=reconstruct_direct_call_closure(export,'caller')
    limit=len(complete['structured_c_source'].encode('utf-8'))+64
    assert len(module._bytes(complete))>limit
    monkeypatch.setattr(module,'MAX_OUTPUT_BYTES',limit,raising=False)
    report=reconstruct_direct_call_closure(export,'caller')
    assert report['status']=='unsupported' and 'call_closure_output_budget' in report['errors']
    assert report.get('ctree') is None and len(module._bytes(report))<=limit


def nested_export(tmp_path):
    export=make_export(tmp_path);clone_function(export,'mid','ram:401140',call_target='ram:401100')
    caller=deepcopy(export.get_unique_function('caller').pcode_ir)
    next(v for v in caller['varnodes'] if v['id']=='callee')['offset']='401140'
    replace_function(export,'caller',caller)
    return export


def void_export(tmp_path):
    export=make_export(tmp_path)
    callee=deepcopy(export.get_unique_function('callee').pcode_ir);callee['operations'][-1]['inputs']=['c0']
    replace_function(export,'callee',callee)
    caller=deepcopy(export.get_unique_function('caller').pcode_ir)
    caller['varnodes']=[v for v in caller['varnodes'] if v['id']!='v2']
    caller['operations'][0]['output']=None;caller['operations'][-1]['inputs']=['c0']
    observation=deepcopy(export.get_unique_function('caller').high_parameter_observation)
    observation['parameters'][0]['instances']=dict(available=True,total=1,omitted=0,observed=['v0'])
    replace_function(export,'caller',caller,observation)
    return export


def stack_loop_export(tmp_path,*,overlap=False):
    export=loop_export(tmp_path);data=deepcopy(export.get_unique_function('caller').pcode_ir)
    data['context']['spaces'].append(dict(name='stack',id=4,bits=64,word_size=1,kind='stack'))
    next(v for v in data['varnodes'] if v['id']=='acc').update(kind='stack',space='stack',offset='fffffffffffffff0')
    if overlap:next(v for v in data['varnodes'] if v['id']=='index').update(kind='stack',space='stack',offset='fffffffffffffff2')
    replace_function(export,'caller',data)
    return export


def test_disjoint_definition_only_stack_ssa_can_be_modeled_as_private_values(tmp_path):
    report=reconstruct_direct_call_closure(stack_loop_export(tmp_path),'caller')
    assert report['status']=='complete',report
    root=next(f for f in report['call_model']['functions'] if f['label']=='caller')
    assert len(root['private_stack_slots'])==1


def test_overlapping_stack_storage_is_not_converted_into_independent_locals(tmp_path):
    report=reconstruct_direct_call_closure(stack_loop_export(tmp_path,overlap=True),'caller')
    assert report['status']=='unsupported' and 'call_closure_stack_overlap' in report['errors']


def test_stack_inputs_need_an_argument_frame_profile_not_local_ssa_assumptions(tmp_path):
    export=make_export(tmp_path);data=deepcopy(export.get_unique_function('caller').pcode_ir)
    data['context']['spaces'].append(dict(name='stack',id=4,bits=64,word_size=1,kind='stack'))
    data['varnodes'][0].update(kind='stack',space='stack',offset='8')
    replace_function(export,'caller',data)
    report=reconstruct_direct_call_closure(export,'caller')
    assert report['status']=='unsupported' and 'call_closure_stack_input_unmodeled' in report['errors']
