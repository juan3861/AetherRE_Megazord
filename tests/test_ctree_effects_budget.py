"""Explicit bounded capacity; default remains256, no guard deletion."""
import pytest
from aether_re.ctree_structuring import structure_control_flow

def cfg(count):
    nodes=['n'+str(i) for i in range(count)]
    edges=[(nodes[i],nodes[i+1]) for i in range(count-1)]
    semantics={name:dict(statements=['r += 1ULL;'],terminator=(dict(kind='return',value='r') if i==count-1 else dict(kind='jump',target=nodes[i+1]))) for i,name in enumerate(nodes)}
    return nodes,edges,semantics

def recover(count,**options):
    nodes,edges,semantics=cfg(count)
    return structure_control_flow(nodes,edges,{},[],'n0',block_semantics=semantics,
        function_signature='unsigned long long recovered(void)',declarations=['unsigned long long r = 0ULL;'],**options)

def test_default_still_refuses_257_nodes():
    report=recover(257)
    assert report['status']=='invalid' and report['structured_c_source'] is None
    assert 'invalid_nodes_or_node_budget' in report['errors']

def test_explicit_bounded_512_preserves_360_blocks_and_statements():
    report=recover(360,node_budget=512)
    assert report['status']=='complete',report
    assert report['node_budget']==512 and report['total_nodes']==360
    assert set(report['emitted_blocks'])==set(cfg(360)[0])
    assert report['structured_c_source'].count('r += 1ULL;')==360

def test_explicit_budget_refuses_513_nodes():
    report=recover(513,node_budget=512)
    assert report['status']=='invalid' and report['structured_c_source'] is None

@pytest.mark.parametrize('budget',[True,False,0,-1,255,513,512.0,'512',None])
def test_bad_capacity_fails_closed(budget):
    report=recover(1,node_budget=budget)
    assert report['status']=='invalid' and report['structured_c_source'] is None
    assert 'invalid_node_budget' in report['errors']
