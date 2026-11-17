"""Reused private stack storage needs SSA liveness proof, not width coincidence."""
from copy import deepcopy
from pathlib import Path
import runpy
import random
import pytest
from aether_re.call_closure import reconstruct_direct_call_closure

f=runpy.run_path(str(Path(__file__).with_name('test_call_closure.py')))
MODEL='bounded-direct-effects-calls.v1'


def reused_export(tmp_path,*,simultaneous=False,partial=False):
    export=f['make_export'](tmp_path);data=deepcopy(export.get_unique_function('callee').pcode_ir)
    variable=f['helpers']['variable'];operation=f['helpers']['operation'];pc=data['function_address']
    data['context']['spaces'].append(dict(name='stack',id=4,bits=64,word_size=1,kind='stack'))
    a=variable('a',definition='o0');a.update(kind='stack',space='stack',offset='fffffffffffffff0')
    b=variable('b',definition='o1' if simultaneous else 'o2');b.update(kind='stack',space='stack',offset='fffffffffffffff2' if partial else 'fffffffffffffff0')
    data['varnodes'].extend([a,b])
    data['operations']=[operation('o0','COPY',['v0'],'a',pc=pc)]
    if simultaneous:
        data['operations'] += [operation('o1','COPY',['v1'],'b',pc=pc,time=1),
            operation('o2','INT_ADD',['a','b'],'v2',pc=pc,time=2),operation('o3','RETURN',['c0','v2'],pc=pc,time=3)]
        next(v for v in data['varnodes'] if v['id']=='v2')['definition']='o2'
    else:
        data['varnodes'].append(variable('saved',definition='o1'))
        data['operations'] += [operation('o1','COPY',['a'],'saved',pc=pc,time=1),
            operation('o2','COPY',['v1'],'b',pc=pc,time=2),operation('o3','INT_ADD',['saved','b'],'v2',pc=pc,time=3),
            operation('o4','RETURN',['c0','v2'],pc=pc,time=4)]
        next(v for v in data['varnodes'] if v['id']=='v2')['definition']='o3'
    data['blocks'][0]['operations']=[o['id'] for o in data['operations']]
    f['replace_function'](export,'callee',data)
    return export


def phi_reuse_export(tmp_path,*,keep_old_live=False):
    export=f['loop_export'](tmp_path);data=deepcopy(export.get_unique_function('caller').pcode_ir)
    data['context']['spaces'].append(dict(name='stack',id=4,bits=64,word_size=1,kind='stack'))
    initial=f['helpers']['variable']('initial',definition='initialize')
    initial.update(kind='stack',space='stack',offset='fffffffffffffff0');data['varnodes'].append(initial)
    next(v for v in data['varnodes'] if v['id']=='acc').update(kind='stack',space='stack',offset='fffffffffffffff0')
    data['operations'].insert(1,f['helpers']['operation']('initialize','COPY',['v1'],'initial',time=1))
    branch=next(o for o in data['operations'] if o['id']=='o1');branch['sequence'].update(time=2,order=2)
    next(o for o in data['operations'] if o['id']=='o3')['inputs'][0]='initial'
    data['blocks'][0]['operations'].insert(1,'initialize')
    if keep_old_live:data['operations'][-1]['inputs'][-1]='initial'
    f['replace_function'](export,'caller',data)
    return export


@pytest.mark.parametrize('partial',[False,True])
def test_noninterfering_private_reuse_requires_an_explicit_proof(tmp_path,partial):
    report=reconstruct_direct_call_closure(reused_export(tmp_path,partial=partial),'caller',call_model=MODEL)
    assert report['status']=='complete',report
    callee=next(i for i in report['call_model']['functions'] if i['label']=='callee')
    assert callee['stack_reuse_proof']['status']=='noninterfering'
    assert callee['stack_reuse_proof']['overlap_pairs']==1
    assert callee['stack_reuse_proof']['original_stack_frame_recovered'] is False


def test_existing_pure_profile_keeps_its_disjoint_storage_contract(tmp_path):
    report=reconstruct_direct_call_closure(reused_export(tmp_path),'caller')
    assert report['status']=='unsupported' and report['errors']==['call_closure_stack_overlap']


@pytest.mark.parametrize('partial',[False,True])
def test_simultaneously_live_overlapping_stack_values_are_refused(tmp_path,partial):
    report=reconstruct_direct_call_closure(reused_export(tmp_path,simultaneous=True,partial=partial),'caller',call_model=MODEL)
    assert report['status']=='unsupported' and report['errors']==['call_closure_stack_interference']


def test_phi_inputs_are_live_on_the_incoming_edge_not_after_the_definition(tmp_path):
    report=reconstruct_direct_call_closure(phi_reuse_export(tmp_path),'caller',call_model=MODEL)
    assert report['status']=='complete',report
    root=next(i for i in report['call_model']['functions'] if i['label']=='caller')
    assert root['stack_reuse_proof']['method']=='backward-ssa-liveness-phi-edges.v1'


def test_phi_reuse_cannot_hide_an_old_value_that_is_still_live(tmp_path):
    report=reconstruct_direct_call_closure(phi_reuse_export(tmp_path,keep_old_live=True),'caller',call_model=MODEL)
    assert report['status']=='unsupported' and report['errors']==['call_closure_stack_interference']


def test_linear_interference_matches_an_independent_last_use_oracle():
    from aether_re.stack_liveness import prove_stack_slot_reuse
    rng=random.Random(2026103016);decisions=[]
    for case in range(128):
        data=f['helpers']['scalar_ir']();data['context']['spaces'].append(dict(name='stack',id=4,bits=64,word_size=1,kind='stack'))
        data['varnodes']=[v for v in data['varnodes'] if v['id']!='v2'];data['operations']=[]
        available=['v0','v1'];slots=[];definition={};last={}
        for index in range(8):
            name='r'+str(index);opcode=rng.choice(['COPY','INT_ADD'])
            operands=[rng.choice(available) for _ in range(1 if opcode=='COPY' else 2)]
            node=f['helpers']['variable'](name,definition='o'+str(index))
            if index>=6 or rng.randrange(4):
                node.update(kind='stack',space='stack',offset=format(0x1000+(0 if index>=6 else rng.choice([0,2,8,12])),'x'))
                slots.append((name,'stack',node['offset'],4));definition[name]=index;last[name]=-1
            data['varnodes'].append(node);available.append(name)
            data['operations'].append(f['helpers']['operation']('o'+str(index),opcode,operands,name,time=index))
        data['operations'].append(f['helpers']['operation']('return','RETURN',['c0','r7'],time=8))
        data['blocks'][0]['operations']=[o['id'] for o in data['operations']]
        assert f['helpers']['analyze'](data)['summary']['status']=='structurally_valid'
        for index,operation in enumerate(data['operations']):
            for identity in operation['inputs']:
                if identity in last:last[identity]=index
        interference=False
        for i,a in enumerate(slots):
            for b in slots[i+1:]:
                overlap=int(a[2],16)<int(b[2],16)+4 and int(b[2],16)<int(a[2],16)+4
                earlier,later=(a[0],b[0]) if definition[a[0]]<definition[b[0]] else (b[0],a[0])
                interference |= overlap and last[earlier]>definition[later]
        if interference:
            with pytest.raises(ValueError,match='call_closure_stack_interference'):prove_stack_slot_reuse(data,slots)
        else:
            result=prove_stack_slot_reuse(data,slots)
            assert result['status']=='noninterfering' and result['overlap_pairs']>=1
        decisions.append(interference)
    assert any(decisions) and not all(decisions)


def test_liveness_budget_exhaustion_cannot_create_an_admission(tmp_path,monkeypatch):
    import aether_re.stack_liveness as module
    monkeypatch.setattr(module,'MAX_VISITS',0)
    report=reconstruct_direct_call_closure(reused_export(tmp_path),'caller',call_model=MODEL)
    assert report['status']=='unsupported' and report['errors']==['call_closure_stack_liveness_budget']
