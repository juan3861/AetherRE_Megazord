"""Symbolic relocation seam for conditional frame IR, without arena admission."""
from __future__ import annotations
from copy import deepcopy
from .frame_derivation import derive_frame_program,_digest,_checked_ir
from .frame_conservation import check_frame_transport
from .frame_usage import prove_frame_usage

MAX=(1<<64)-1

def _require(value,reason):
    if not value:raise ValueError('frame_relocation_'+reason)

def _domain(fact,base):
    _require(type(fact) is dict,'fact')
    delta=fact.get('entry_rsp_offset');extent=fact.get('requested_object_bytes')
    _require(type(delta) is int and -(1<<63)<=delta<1<<63,'delta')
    _require(type(extent) is int and 1<=extent<=4096,'extent')
    _require(type(base) is int and 0<=base<=MAX and base%16==0,'base')
    entry=base-delta
    _require(0<=entry<=MAX and extent-1<=MAX-base,'domain_overflow')
    return delta,extent,entry

def _anchor(fact):
    _require(type(fact) is dict and type(fact.get('entry_rsp_offset')) is int,'fact')
    delta=fact['entry_rsp_offset']
    base=max(0,((delta+15)//16)*16)
    _domain(fact,base)
    return base

def _constant(ir,fact,base):
    delta,extent,entry=_domain(fact,base)
    result=deepcopy(ir)
    node=next(n for n in result['varnodes'] if n['id']==fact['ambient_varnode'])
    node.update(space='const',kind='constant',offset=format(entry,'x'),input=False,free=True,unaffected=False)
    return result,dict(object_base=base,object_bytes=extent,abstract_entry=entry,entry_offset=delta)

def derive_relocatable_frame(root,callee,fact):
    """Preserve the source ambient input; original exports remain unchanged."""
    try:
        base=_anchor(fact)
        usage=prove_frame_usage(root=root,callees=[callee],frame_fact=fact)
        fixed=derive_frame_program(root['pcode_ir'],callee,fact,object_base=base)
        check_frame_transport(root,callee,fact,fixed,usage,object_base=base)
        ir=deepcopy(fixed['derived_ir']);ambient=fact['ambient_varnode']
        original=next(n for n in root['pcode_ir']['varnodes'] if n['id']==ambient)
        ir['varnodes']=[deepcopy(original) if n['id']==ambient else n for n in ir['varnodes']]
        packet=dict(schema='relocatable-frame-ir.v1',status='conditional_model',derived_ir=ir,
            static_provenance=deepcopy(fixed['provenance']),
            relocation=dict(ambient_varnode=ambient,source_delta=fact['entry_rsp_offset'],
                object_bytes=fact['requested_object_bytes'],reference_base=base,
                symbolic_sha256=_digest(ir),entry_rule='abstract_entry = checked_object_base - source_delta'),
            placement_domain_enforced=False,native_frame_fact_verified=False,production_admission=False,
            abi_recovered=False,binary_equivalence_proved=False,original_source_recovered=False)
        check_frame_relocation(root,callee,fact,packet)
        return packet
    except (KeyError,TypeError,IndexError,StopIteration,AttributeError) as error:
        raise ValueError('frame_relocation_envelope') from error

def check_frame_relocation(root,callee,fact,packet):
    """Re-specialize then check exact operation/operand/metadata transport."""
    try:
        flags=('placement_domain_enforced','native_frame_fact_verified','production_admission',
               'abi_recovered','binary_equivalence_proved','original_source_recovered')
        _require(type(packet) is dict and set(packet)=={'schema','status','derived_ir','static_provenance','relocation',*flags},'fields')
        _require(packet['schema']=='relocatable-frame-ir.v1' and packet['status']=='conditional_model','schema')
        for flag in flags:
            _require(packet[flag] is False,'claim')
        proof=packet['static_provenance']
        _require(type(proof) is dict and set(proof)=={'schema','caller_sha256','callee_sha256',
            'frame_fact_sha256','derived_sha256','operations','formal_mapping','callee_varnode_renaming',
            'callee_operation_renaming','return_identity','source_blocks','frame',*flags[1:]},'provenance_fields')
        _require(proof['schema']=='frame-derivation-provenance.v1','provenance_schema')
        for flag in flags[1:]:_require(proof[flag] is False,'provenance_claim')
        _require(proof['source_blocks']==dict(caller=root['pcode_ir']['blocks'],callee=callee['pcode_ir']['blocks']),'source_blocks')
        ir=packet['derived_ir'];base=_anchor(fact);ambient=fact['ambient_varnode']
        original=next(n for n in root['pcode_ir']['varnodes'] if n['id']==ambient)
        matches=[n for n in ir['varnodes'] if n['id']==ambient]
        _require(len(matches)==1 and matches[0]==original,'symbolic_input')
        expected=dict(ambient_varnode=ambient,source_delta=fact['entry_rsp_offset'],
            object_bytes=fact['requested_object_bytes'],reference_base=base,symbolic_sha256=_digest(ir),
            entry_rule='abstract_entry = checked_object_base - source_delta')
        _require(packet['relocation']==expected,'binding')
        _checked_ir(ir,_digest(ir))
        fixed,frame=_constant(ir,fact,base)
        _require(packet['static_provenance']['frame']==frame,'reference_frame')
        usage=prove_frame_usage(root=root,callees=[callee],frame_fact=fact)
        links=check_frame_transport(root,callee,fact,dict(derived_ir=fixed,provenance=packet['static_provenance']),usage,object_base=base)
        return dict(schema='frame-relocation-check.v1',memory_links=links,symbolic_sha256=_digest(ir),
            source_ir_sha256=_digest(root['pcode_ir']),placement_domain_enforced=False,production_admission=False)
    except (KeyError,TypeError,IndexError,StopIteration,AttributeError) as error:
        raise ValueError('frame_relocation_envelope') from error

def specialize_frame_relocation(root,callee,fact,packet,*,object_base):
    """Checked mathematical placement; this does not allocate a runtime frame."""
    check_frame_relocation(root,callee,fact,packet)
    ir,frame=_constant(packet['derived_ir'],fact,object_base)
    proof=deepcopy(packet['static_provenance']);proof['frame']=frame;proof['derived_sha256']=_digest(ir)
    usage=prove_frame_usage(root=root,callees=[callee],frame_fact=fact)
    check_frame_transport(root,callee,fact,dict(derived_ir=ir,provenance=proof),usage,object_base=object_base)
    _checked_ir(ir,_digest(ir))
    return ir

def emit_relocatable_frame_body(root,callee,fact):
    """Emit the symbolic IR literally; allocation/domain/lifetime guards are external."""
    from .ghidra_pcode_c import reconstruct_high_pcode
    packet=derive_relocatable_frame(root,callee,fact);ir=packet['derived_ir']
    emitted=reconstruct_high_pcode(ir,expected_target=ir['target_sha256'],
        expected_address=ir['function_address'],evidence_sha256=_digest(ir),
        function_name='aether_relocatable_body',memory_model='bounded-bytes.v2',internal_linkage=True)
    _require(emitted['status']=='complete','emitter_refused')
    bindings=[b for b in emitted['input_bindings'] if b['varnode']==fact['ambient_varnode']]
    _require(len(bindings)==1,'emitter_ambient_binding')
    return dict(schema='relocatable-frame-body.v1',status='conditional_body',packet=packet,
        emitted=emitted,abstract_entry_parameter=bindings[0]['parameter'],
        runtime_domain_guard_required=True,placement_domain_enforced=False,
        native_frame_fact_verified=False,production_admission=False,abi_recovered=False,
        binary_equivalence_proved=False,original_source_recovered=False,
        limitations=['literal symbolic derived body; caller must enforce placement/entry/extent domain',
                    'allocation,invocation tokens,lifetime,descriptor fencing and native admission remain unproved'])
