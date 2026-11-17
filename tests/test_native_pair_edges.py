"""Additional concrete cases identified by the internal static review."""
import functools,operator
import pytest
from test_native_leaf_data import inputs,bind
from test_native_caller_data import observe,module

def test_same_address_stores_supply_the_last_value_to_both_loads():
    raw,root,callee,language=inputs()
    raw=bytearray(raw)
    raw[512+0x270+17]=0
    raw[512+0x290+26]=0
    next(node for node in callee['pcode_ir']['varnodes'] if node['id']=='v65')['offset']='0'
    next(node for node in root['pcode_ir']['varnodes'] if node['id']=='v184')['offset']='0'
    bind(raw,root,callee)
    report=observe((bytes(raw),root,callee,language))
    first,second,left,right=report['events']
    assert first['address']==second['address']==left['address']==right['address']
    assert left['value']==right['value']==second['value']
    assert report['return_expression']==('constant',0)

def test_xor_repeated_terms_cancel_with_odd_and_even_multiplicity():
    data=module();x=('input','x');y=('input','y')
    assert data.combine('xor',x,y,x,x,y)==x
    assert data.combine('xor',x,x,y,y,data.constant(data.MASK),data.constant(data.MASK))==data.constant(0)

def test_associative_unsigned_addition_wraps_at_word_boundary():
    data=module();x=('input','x')
    expression=data.combine('add',data.constant(data.MASK),data.combine('add',x,data.constant(2)))
    assert expression==data.combine('add',x,data.constant(1))
    def evaluate(node,value):
        if node[0]=='input':return value
        if node[0]=='constant':return node[1]
        terms=[evaluate(part,value) for part in node[1:]]
        return (sum(terms) if node[0]=='add' else functools.reduce(operator.xor,terms))&data.MASK
    for value in (0,1,(1<<32)-1,1<<63,data.MASK-1,data.MASK):
        assert evaluate(expression,value)==(value+1)&data.MASK

def test_post_call_r8_address_use_requires_a_proven_value():
    raw,root,callee,language=inputs();raw=bytearray(raw)
    raw[512+0x290+20]=0x49
    next(op for op in root['pcode_ir']['operations'] if op['id']=='o3')['inputs'][1]='v123'
    bind(raw,root,callee)
    with pytest.raises(ValueError,match='unproved_call_clobber_use'):
        observe((bytes(raw),root,callee,language))
