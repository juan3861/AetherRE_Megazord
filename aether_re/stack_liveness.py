"""Conservative storage interference for validated, private High P-Code SSA.

This is not original stack-frame or machine alias recovery. Callers must first
validate IR identity/SSA, definition-only stack values and the private domain.
"""
import hashlib
import json

MAX_VISITS=100000


def _digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),
        ensure_ascii=False,allow_nan=False).encode('utf-8')).hexdigest()


def prove_stack_slot_reuse(data,slots):
    """Return a bound noninterference summary, or None when ranges are disjoint."""
    if len(slots)<2:return None
    if len(slots)>800 or len(data['varnodes'])>800 or len(data['operations'])>900 or len(data['blocks'])>512:
        raise ValueError('call_closure_stack_liveness_budget')
    slots=sorted(slots,key=lambda s:s[0]);bits={s[0]:1<<i for i,s in enumerate(slots)}
    if len(bits)!=len(slots):raise ValueError('call_closure_stack_liveness_input')
    neighbors=[0]*len(slots);pairs=[]
    for i,a in enumerate(slots):
        for j in range(i+1,len(slots)):
            b=slots[j]
            if a[1]==b[1] and int(a[2],16)<int(b[2],16)+b[3] and int(b[2],16)<int(a[2],16)+a[3]:
                neighbors[i]|=1<<j;neighbors[j]|=1<<i;pairs.append((a[0],b[0]))
    if not pairs:return None
    blocks={b['id']:b for b in data['blocks']};operations={o['id']:o for o in data['operations']}
    uses={};defs={};phi_defs={};edge_uses={};phi_ops={}
    def inputs(operation):
        result=0
        for identity in operation['inputs']:result|=bits.get(identity,0)
        return result
    for identity,block in blocks.items():
        used=defined=phi_defined=0;phis=[];regular=False
        for name in block['operations']:
            operation=operations[name];output=bits.get(operation.get('output'),0)
            if operation['opcode']=='MULTIEQUAL':
                if regular or len(operation['inputs'])!=len(block['predecessors']):
                    raise ValueError('call_closure_stack_liveness_input')
                phis.append(operation);phi_defined|=output
                for index,pred in enumerate(block['predecessors']):
                    key=(pred['block'],pred['source_slot'],identity)
                    edge_uses[key]=edge_uses.get(key,0)|bits.get(operation['inputs'][index],0)
            else:
                regular=True;used|=inputs(operation)&~defined
            defined|=output
        uses[identity]=used;defs[identity]=defined;phi_defs[identity]=phi_defined;phi_ops[identity]=phis
    live_in={i:0 for i in blocks};live_out=dict(live_in);visits=rounds=0;changed=True
    while changed:
        changed=False;rounds+=1
        for identity in reversed(list(blocks)):
            visits+=1
            if visits>MAX_VISITS:raise ValueError('call_closure_stack_liveness_budget')
            out=0
            for slot,edge in enumerate(blocks[identity]['successors']):
                target=edge['block']
                out|=(live_in[target]&~phi_defs[target])|edge_uses.get((identity,slot,target),0)
            incoming=uses[identity]|(out&~defs[identity])
            if out!=live_out[identity] or incoming!=live_in[identity]:changed=True
            live_out[identity]=out;live_in[identity]=incoming
    points=0
    def check(live):
        nonlocal points
        points+=1
        for index,adjacent in enumerate(neighbors):
            if live&(1<<index) and adjacent&live:
                raise ValueError('call_closure_stack_interference')
    for identity,block in blocks.items():
        live=live_out[identity];check(live);check(live_in[identity])
        regular=[operations[i] for i in block['operations'] if operations[i]['opcode']!='MULTIEQUAL']
        for operation in reversed(regular):
            output=bits.get(operation.get('output'),0)
            check(live|output) # Even a dead definition writes its private storage.
            live=(live&~output)|inputs(operation);check(live)
        # Phi definitions are parallel; their inputs live on predecessor edges.
        check(live|phi_defs[identity]);live&=~phi_defs[identity];check(live)
        if live!=live_in[identity]:raise ValueError('call_closure_stack_liveness_input')
    facts=[(i,format(live_in[i],'x'),format(live_out[i],'x')) for i in sorted(blocks)]
    return dict(status='noninterfering',method='backward-ssa-liveness-phi-edges.v1',
        ir_payload_sha256=_digest(data),overlap_pairs=len(pairs),overlap_pairs_sha256=_digest(pairs),
        fixed_point_rounds=rounds,block_visits=visits,checked_program_points=points,
        liveness_sha256=_digest(dict(slots=slots,block_facts=facts)),
        model_scope='definition-only private High P-Code SSA values',requires_validated_ir=True,
        original_stack_frame_recovered=False,binary_aliasing_proved=False)
