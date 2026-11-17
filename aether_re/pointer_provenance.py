"""Bounded conditional abstract-address derivation, never original RAM/ABI proof.

Requires structurally validated SSA and independently admitted private storage.
Roots are caller hypotheses associated with observed parameter instances.
"""
import hashlib
import json
import re

MAX_VISITS = 100000


def _digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),
        ensure_ascii=False,allow_nan=False).encode('utf-8')).hexdigest()


def prove_pointer_provenance(data,address_formals,*,observation_sha256,extra_sinks=(),max_visits=MAX_VISITS):
    """Prove every reachable derivation component has a declared external root.

    A seeded arm never excuses a second closed, unseeded PHI component. Numeric
    constants and loaded values cannot serve as address roots. Storage offsets
    are never interpreted as addresses. Widths retain existing modular semantics.
    """
    def refuse(reason):raise ValueError('call_closure_pointer_provenance_'+reason)
    if type(max_visits) is not int or not 1<=max_visits<=MAX_VISITS:refuse('budget')
    if len(data['varnodes'])>800 or len(data['operations'])>900:refuse('budget')
    if type(observation_sha256) is not str or not re.fullmatch('[0-9a-f]{64}',observation_sha256):refuse('observation')
    nodes={v['id']:v for v in data['varnodes']};operations={o['id']:o for o in data['operations']}
    roots=set(address_formals);width=data['context']['address_bits']//8
    if width not in (1,2,4,8):refuse('width')
    if any(v['kind']=='stack' and (v['input'] or not v.get('definition')) for v in nodes.values()):refuse('stack_input')
    for identity in roots:
        v=nodes.get(identity)
        if v is None or not v['input'] or v['kind'] not in ('register','unique') or v['size']!=width:refuse('input')
    sinks=set(extra_sinks)
    for op in operations.values():
        if op['opcode'] in ('PTRADD','PTRSUB'):
            sinks.update((op['inputs'][0],op['output']))
        if op['opcode'] in ('LOAD','STORE'):sinks.add(op['inputs'][1])
    pending=list(sorted(sinks));dependencies={};origins={};visits=0
    while pending:
        identity=pending.pop()
        if identity in dependencies:continue
        visits+=1
        if visits>max_visits:refuse('budget')
        v=nodes.get(identity)
        if v is None or v['size']!=width:refuse('width')
        if v['input']:
            if identity not in roots:refuse('unknown_input')
            dependencies[identity]=();origins[identity]={identity};continue
        definition=operations.get(v.get('definition'))
        if definition is None:refuse('unknown_address')
        opcode=definition['opcode'];inputs=definition['inputs']
        if opcode in ('COPY','CAST') and len(inputs)==1:args=tuple(inputs)
        elif opcode=='MULTIEQUAL' and inputs:args=tuple(inputs)
        elif opcode in ('PTRADD','PTRSUB') and len(inputs)==(3 if opcode=='PTRADD' else 2):
            if any(nodes[i]['kind']!='constant' for i in inputs[1:]):refuse('offset')
            args=(inputs[0],)
        else:refuse('definition:'+opcode)
        dependencies[identity]=args;origins[identity]=set();pending.extend(args)
    rounds=0;changed=True
    while changed:
        rounds+=1;changed=False
        for identity,args in dependencies.items():
            visits+=1+len(args)
            if visits>max_visits:refuse('budget')
            reached=origins[identity].union(*(origins[arg] for arg in args))
            if reached!=origins[identity]:origins[identity]=reached;changed=True
    if any(not found for found in origins.values()):refuse('unseeded_component')
    used=sorted(set().union(*origins.values())) if origins else []
    facts=[dict(varnode=i,inputs=list(dependencies[i]),formal_roots=sorted(origins[i])) for i in sorted(dependencies)]
    return dict(schema='conditional-external-address-derivation.v1',status='conditional_address_derivation',
        ir_payload_sha256=_digest(data),observation_sha256=observation_sha256,
        declared_address_formals=sorted(roots),used_address_formals=used,sinks=sorted(sinks),
        derivations=facts,derivations_sha256=_digest(facts),fixed_point_rounds=rounds,visits=visits,
        visit_limit=max_visits,requires_validated_ir=True,
        hypothesis='observed pointer formal values designate caller-supplied abstract external byte addresses',
        original_ram_pointer_proved=False,original_stack_frame_recovered=False,
        abi_recovered=False,binary_equivalence_proved=False)
