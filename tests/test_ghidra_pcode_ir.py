from copy import deepcopy

import pytest

from aether_re.ghidra_pcode_ir import analyze_high_pcode

TARGET='a'*64
ADDRESS='ram:401000'
EVIDENCE='b'*64


def variable(identity,kind='unique',size=4,offset='0',definition=None,input=False):
    space={'constant':'const','register':'register','unique':'unique','memory':'ram'}[kind]
    return dict(id=identity,kind=kind,space=space,offset=offset,size=size,definition=definition,input=input,free=False)


def operation(identity,opcode,inputs,output=None,pc=ADDRESS,time=0,**extra):
    return dict(id=identity,opcode=opcode,inputs=inputs,output=output,sequence=dict(pc=pc,time=time,order=time),**extra)


def scalar_ir():
    return dict(schema='ghidra-high-pcode.v1',target_sha256=TARGET,function_address=ADDRESS,entry_block='b0',complete=True,
        context=dict(language_id='x86:LE:64:default',compiler_spec_id='windows',endian='little',address_bits=64,image_base='ram:400000',
            spaces=[dict(name=name,id=i,bits=64,word_size=1,kind=kind) for i,(name,kind) in enumerate([('ram','memory'),('register','register'),('unique','unique'),('const','constant')])]),
        blocks=[dict(id='b0',start=ADDRESS,stop='ram:401007',predecessors=[],successors=[],operations=['o0','o1'])],
        varnodes=[variable('v0','register',offset='8',input=True),variable('v1','register',offset='10',input=True),
            variable('v2',definition='o0'),variable('c0','constant',8)],
        operations=[operation('o0','INT_ADD',['v0','v1'],'v2'),operation('o1','RETURN',['c0','v2'],time=1)])


def analyze(data):
    return analyze_high_pcode(data,expected_target=TARGET,expected_address=ADDRESS,evidence_sha256=EVIDENCE)


def phi_ir():
    data=scalar_ir()
    data['varnodes']=[variable('v0','register',input=True),variable('c0','constant'),variable('cond',size=1,definition='o0'),
        variable('c7','constant',offset='7'),variable('c9','constant',offset='9'),
        variable('left',definition='o2'),variable('right',definition='o4'),variable('merged',definition='o6'),
        variable('target_left','memory',8,'401010'),variable('target_join','memory',8,'401030'),variable('ret','constant',8)]
    data['operations']=[operation('o0','INT_SLESS',['c0','v0'],'cond'),operation('o1','CBRANCH',['target_left','cond'],time=1),
        operation('o2','COPY',['c7'],'left',pc='ram:401010'),operation('o3','BRANCH',['target_join'],pc='ram:401010',time=1),
        operation('o4','COPY',['c9'],'right',pc='ram:401020'),operation('o5','BRANCH',['target_join'],pc='ram:401020',time=1),
        operation('o6','MULTIEQUAL',['left','right'],'merged',pc='ram:401030',phi_predecessors=['b1','b2']),
        operation('o7','RETURN',['ret','merged'],pc='ram:401030',time=1)]
    data['blocks']=[
        dict(id='b0',start=ADDRESS,stop='ram:401007',predecessors=[],successors=[{'block':'b2','target_slot':0},{'block':'b1','target_slot':0}],operations=['o0','o1'],true_out='b1',false_out='b2'),
        dict(id='b1',start='ram:401010',stop='ram:401017',predecessors=[{'block':'b0','source_slot':1}],successors=[{'block':'b3','target_slot':0}],operations=['o2','o3']),
        dict(id='b2',start='ram:401020',stop='ram:401027',predecessors=[{'block':'b0','source_slot':0}],successors=[{'block':'b3','target_slot':1}],operations=['o4','o5']),
        dict(id='b3',start='ram:401030',stop='ram:401037',predecessors=[{'block':'b1','source_slot':0},{'block':'b2','source_slot':0}],successors=[],operations=['o6','o7']),
    ]
    return data


def test_real_shape_preserves_width_and_def_use_in_existing_ir_graph():
    result=analyze(scalar_ir())
    assert result['summary']['status']=='structurally_valid'
    assert result['summary']['dominance_checked'] is True
    assert result['summary']['semantic_equivalence_proved'] is False
    graph=result['graph']
    assert graph['schema']=='ir.v1'
    variables=[node for node in graph['nodes'] if node['kind']=='pcode-varnode']
    assert len(variables)==4 and all(node['attributes']['size'] in (4,8) for node in variables)
    assert any(edge['kind']=='definition' for edge in graph['edges'])
    assert all('sha256:'+EVIDENCE in node['evidence_refs'] for node in graph['nodes'])


def test_phi_retains_operand_predecessor_slots_and_true_false_edges():
    result=analyze(phi_ir())
    assert result['summary']['phi_operations']==1
    edges=[edge for edge in result['graph']['edges'] if edge['kind']=='operand' and 'predecessor' in edge['attributes']]
    assert [(e['attributes']['slot'],e['attributes']['predecessor']) for e in sorted(edges,key=lambda e:e['attributes']['slot'])]==[(0,'b1'),(1,'b2')]


@pytest.mark.parametrize('mutate',[
    lambda d:d.update(target_sha256='c'*64),
    lambda d:d['varnodes'][2].update(size=8),
    lambda d:d['operations'][0].update(inputs=['missing','v1']),
    lambda d:d['varnodes'][2].update(definition='o1'),
    lambda d:d['operations'][1].update(output='v2'),
    lambda d:d['blocks'][0].update(operations=['o1','o0']),
    lambda d:d['blocks'][0].update(operations=['o0','o0','o1']),
    lambda d:d['operations'][1]['sequence'].update(time=0),
    lambda d:d.update(semantic_equivalence_proved=True),
])
def test_invalid_identity_width_references_or_definitions_abstain(mutate):
    data=scalar_ir();mutate(data)
    with pytest.raises(ValueError): analyze(data)


@pytest.mark.parametrize('mutate',[
    lambda d:d['operations'][6].update(phi_predecessors=['b2','b1']),
    lambda d:d['operations'][6].update(inputs=['left']),
    lambda d:d['blocks'][0]['successors'][0].update(target_slot=1),
    lambda d:d['operations'][6].update(inputs=['right','left']),
    lambda d:d['blocks'][0].update(true_out='b2'),
])
def test_phi_cfg_and_dominance_contradictions_are_rejected(mutate):
    data=phi_ir();mutate(data)
    with pytest.raises(ValueError): analyze(data)


def test_unknown_operations_and_calls_are_preserved_as_unproved_effects():
    data=scalar_ir();data['operations'][0]['opcode']='FUTURE_OPERATION'
    result=analyze(data)
    assert result['summary']['effects']['unmodeled']==['o0']
    assert any(node['attributes'].get('opcode')=='FUTURE_OPERATION' for node in result['graph']['nodes'])
    data=scalar_ir();data['operations'][0]['opcode']='CALLIND'
    data['varnodes'].append(variable('fn','register',8,offset='18',input=True))
    data['operations'][0]['inputs']=['fn','v0','v1']
    result=analyze(data)
    assert result['summary']['effects']['calls']==['o0']
    assert result['summary']['semantic_equivalence_proved'] is False


def test_noninput_without_definition_is_reported_not_invented():
    data=scalar_ir();data['varnodes'][0]['input']=False;data['varnodes'][0]['free']=True
    result=analyze(data)
    assert result['summary']['unresolved_liveins']==['v0']


def test_inventory_budgets_reject_before_projection():
    data=scalar_ir();data['blocks']*=4097
    with pytest.raises(ValueError): analyze(data)


@pytest.mark.parametrize('opcode',['CALLIND','BRANCHIND'])
def test_indirect_target_is_a_value_and_must_be_defined_before_use(opcode):
    data=scalar_ir()
    data['varnodes'] += [variable('fn_input','register',8,offset='18',input=True),variable('fn_target',size=8,definition='target_def')]
    definition=operation('target_def','COPY',['fn_input'],'fn_target',time=9)
    if opcode=='CALLIND':
        data['operations'][0:0]=[operation('indirect',opcode,['fn_target'],time=8),definition]
        data['blocks'][0]['operations'][0:0]=['indirect','target_def']
    else:
        data['operations'][0:0]=[operation('indirect',opcode,['fn_target'],time=8),definition]
        data['blocks'][0]['start']='ram:401010'
        data['blocks'][0]['stop']='ram:401017'
        data['blocks'][0]['operations'].insert(0,'target_def')
        data['blocks'][0]['predecessors']=[{'block':'first','source_slot':0}]
        data['blocks'].insert(0,dict(id='first',start=ADDRESS,stop='ram:401007',predecessors=[],
            successors=[{'block':'b0','target_slot':0}],operations=['indirect']))
        data['entry_block']='first'
    with pytest.raises(ValueError,match='use_before_definition|does_not_dominate'): analyze(data)


@pytest.mark.parametrize('opcode,inputs,output',[
    ('BOOL_AND',['v0','v1'],'v2'),('PTRADD',[],'v2'),('LOAD',['v0','v1'],'v2'),
    ('STORE',['v0','v1','v2'],None),('BOOL_NEGATE',['v0'],'v2'),('POPCOUNT',[],'v2'),
    ('LZCOUNT',[],'v2'),('INDIRECT',[],'v2'),('PTRSUB',[],'v2'),
])
def test_known_opcode_shape_is_checked_before_structural_acceptance(opcode,inputs,output):
    data=scalar_ir();data['operations'][0].update(opcode=opcode,inputs=inputs,output=output)
    with pytest.raises(ValueError): analyze(data)


def test_two_successors_cannot_survive_removed_branch_instruction():
    data=phi_ir()
    data['operations']=[op for op in data['operations'] if op['id']!='o1']
    data['blocks'][0]['operations'].remove('o1')
    with pytest.raises(ValueError): analyze(data)


def test_known_pure_operation_cannot_replace_terminal_return():
    data=scalar_ir();data['operations'].pop();data['blocks'][0]['operations'].pop()
    with pytest.raises(ValueError): analyze(data)


def test_indirect_call_pointer_width_matches_instruction_address_space():
    data=scalar_ir();data['operations'][0]['opcode']='CALLIND'
    with pytest.raises(ValueError): analyze(data)


def test_high_return_marker_can_be_nonzero_and_smaller_than_machine_pointer():
    # Observed in Ghidra 12.1.4 HighFunction for the owned invoke DLL fixture.
    data=scalar_ir()
    data['varnodes'][3].update(offset='1',size=4)
    result=analyze(data)
    assert result['summary']['status']=='structurally_valid'
    marker=next(node for node in result['graph']['nodes'] if node['kind']=='pcode-varnode' and node['attributes']['id']=='c0')
    assert marker['attributes']['offset']=='1' and marker['attributes']['size']==4
    assert result['summary']['binary_semantics_recovered'] is False


def test_complete_empty_terminal_is_not_a_valid_function():
    data=scalar_ir()
    data['operations']=[];data['varnodes']=[];data['blocks'][0]['operations']=[]
    with pytest.raises(ValueError,match='empty_terminal'): analyze(data)
    data['complete']=False
    assert analyze(data)['summary']['status']=='partial'
