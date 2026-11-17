"""Lower observed scalar High P-Code to the existing C-Tree contract.

Unsigned 64-bit carriers implement explicit 8/16/32/64-bit words. This does
not recover original types/ABI or prove equivalence to the input binary.
"""
from __future__ import annotations

import re

from aether_re.ctree_structuring import structure_control_flow
from aether_re.ghidra_pcode_ir import analyze_high_pcode

_BINARY = {'INT_ADD':'+','INT_SUB':'-','INT_MULT':'*','INT_XOR':'^','INT_AND':'&','INT_OR':'|'}
_CMP = {'INT_EQUAL':'==','INT_NOTEQUAL':'!=','INT_LESS':'<','INT_LESSEQUAL':'<='}
_SUPPORTED = set(_BINARY)|set(_CMP)|set('COPY CAST INT_NEGATE INT_2COMP INT_SLESS INT_SLESSEQUAL INT_CARRY INT_SCARRY INT_SBORROW BOOL_NEGATE BOOL_XOR BOOL_AND BOOL_OR INT_ZEXT INT_SEXT INT_LEFT INT_RIGHT INT_SRIGHT PIECE SUBPIECE PTRADD PTRSUB POPCOUNT LZCOUNT MULTIEQUAL BRANCH CBRANCH RETURN'.split())


class _Unsupported(ValueError):
    pass


_MEMORY_RUNTIME = r'''
#include <limits.h>
_Static_assert(CHAR_BIT == 8 && ULLONG_MAX == 18446744073709551615ULL,
    "bounded bytes require 8-bit bytes and 64-bit unsigned long long");
struct aether_memory_event {
    unsigned long long operation, address, value;
    unsigned int width, kind;
};
struct aether_memory {
    unsigned char *bytes, *permissions, *initialized;
    unsigned long long base, length, space_id, steps_left, steps_executed;
    struct aether_memory_event *events;
    unsigned long long event_capacity, event_count;
    unsigned int status;
};
static int aether_memory_valid(struct aether_memory *m, unsigned long long max_address) {
    if (!m) return 0;
    if (m->status) return 0;
    if (m->length > 1048576ULL || m->event_capacity > 4096ULL ||
        m->event_count > m->event_capacity || m->steps_executed > 1000000ULL ||
        m->steps_left > 1000000ULL - m->steps_executed || m->base > max_address ||
        (m->length && m->length - 1ULL > max_address - m->base) ||
        (m->length && (!m->bytes || !m->permissions || !m->initialized)) ||
        (m->event_capacity && !m->events)) { m->status = 1U; return 0; }
    return 1;
}
static int aether_memory_step(struct aether_memory *m) {
    if (m->status) return 0;
    if (!m->steps_left) { m->status = 2U; return 0; }
    --m->steps_left; ++m->steps_executed; return 1;
}
static int aether_memory_access(struct aether_memory *m, unsigned long long space,
    unsigned long long address, unsigned int width, unsigned int writing) {
    unsigned long long offset; unsigned int i;
    if (m->status) return 0;
    if (space != m->space_id) { m->status = 3U; return 0; }
    if (!width || width > 8U) { m->status = 1U; return 0; }
    if (address < m->base || (unsigned long long)width > m->length) { m->status = 4U; return 0; }
    offset = address - m->base;
    if (offset > m->length - (unsigned long long)width) { m->status = 4U; return 0; }
    for (i = 0; i < width; ++i) {
        if (!(m->permissions[offset+i] & (writing ? 2U : 1U))) { m->status = 5U; return 0; }
        if (!writing && !m->initialized[offset+i]) { m->status = 6U; return 0; }
    }
    if (m->event_count >= m->event_capacity) { m->status = 7U; return 0; }
    return 1;
}
static unsigned long long aether_memory_load(struct aether_memory *m,
    unsigned long long space, unsigned long long address, unsigned int width,
    unsigned int big_endian, unsigned long long operation) {
    unsigned long long value = 0ULL, offset; unsigned int i, shift;
    struct aether_memory_event *event;
    if (!aether_memory_access(m,space,address,width,0U)) return 0ULL;
    offset = address - m->base;
    for (i = 0; i < width; ++i) {
        shift = 8U * (big_endian ? width-1U-i : i);
        value |= ((unsigned long long)m->bytes[offset+i]) << shift;
    }
    event = &m->events[m->event_count++];
    event->operation=operation; event->address=address; event->value=value;
    event->width=width; event->kind=0U;
    return value;
}
static void aether_memory_store(struct aether_memory *m, unsigned long long space,
    unsigned long long address, unsigned int width, unsigned long long value,
    unsigned int big_endian, unsigned long long operation) {
    unsigned long long offset; unsigned int i, shift;
    struct aether_memory_event *event;
    if (!aether_memory_access(m,space,address,width,1U)) return;
    offset = address - m->base;
    for (i = 0; i < width; ++i) {
        shift = 8U * (big_endian ? width-1U-i : i);
        m->bytes[offset+i] = (unsigned char)(value >> shift);
        m->initialized[offset+i] = 1U;
    }
    event = &m->events[m->event_count++];
    event->operation=operation; event->address=address; event->value=value;
    event->width=width; event->kind=1U;
}
'''


_SPARSE_MEMORY_RUNTIME = r'''
#include <limits.h>
_Static_assert(CHAR_BIT == 8 && ULLONG_MAX == 18446744073709551615ULL,
    "bounded regions require 8-bit bytes and 64-bit unsigned long long");
struct aether_sparse_event {
    unsigned long long operation, address, value;
    unsigned int width, kind;
};
struct aether_sparse_region {
    unsigned char *bytes, *permissions, *initialized;
    unsigned long long base, length;
};
struct aether_sparse_memory {
    struct aether_sparse_region *regions;
    unsigned long long region_count, space_id, steps_left, steps_executed;
    struct aether_sparse_event *events;
    unsigned long long event_capacity, event_count;
    unsigned int status;
};
static int aether_sparse_memory_valid(struct aether_sparse_memory *m, unsigned long long max_address) {
    unsigned long long i, total=0ULL, last=0ULL;
    struct aether_sparse_region *r;
    if (!m || m->status) return 0;
    if (m->region_count>128ULL || (m->region_count && !m->regions) ||
        m->event_capacity>4096ULL || m->event_count>m->event_capacity ||
        (m->event_capacity && !m->events) || m->steps_executed>1000000ULL ||
        m->steps_left>1000000ULL-m->steps_executed) { m->status=1U; return 0; }
    for(i=0ULL;i<m->region_count;++i) {
        r=&m->regions[i];
        if (!r->length || r->length>1048576ULL-total || !r->bytes || !r->permissions || !r->initialized ||
            r->base>max_address || r->length-1ULL>max_address-r->base || (i && r->base<=last)) {
            m->status=1U; return 0;
        }
        total+=r->length; last=r->base+r->length-1ULL;
    }
    return 1;
}
static int aether_sparse_memory_step(struct aether_sparse_memory *m) {
    if(m->status) return 0;
    if(!m->steps_left) {m->status=2U;return 0;}
    --m->steps_left;++m->steps_executed;return 1;
}
static struct aether_sparse_region *aether_sparse_memory_find(struct aether_sparse_memory *m,
    unsigned long long address) {
    unsigned long long left=0ULL,right=m->region_count,mid;
    struct aether_sparse_region *r;
    while(left<right) {
        mid=left+(right-left)/2ULL;r=&m->regions[mid];
        if(address<r->base) right=mid;
        else if(address-r->base>=r->length) left=mid+1ULL;
        else return r;
    }
    return 0;
}
static int aether_sparse_memory_access(struct aether_sparse_memory *m, unsigned long long space,
    unsigned long long address, unsigned int width, unsigned int writing,
    struct aether_sparse_region **regions, unsigned long long *offsets) {
    unsigned int i;
    struct aether_sparse_region *r;
    if(m->status) return 0;
    if(space!=m->space_id) {m->status=3U;return 0;}
    if(!width || width>8U) {m->status=1U;return 0;}
    if((unsigned long long)(width-1U)>ULLONG_MAX-address) {m->status=4U;return 0;}
    for(i=0U;i<width;++i) {
        r=aether_sparse_memory_find(m,address+i);
        if(!r) {m->status=4U;return 0;}
        regions[i]=r;offsets[i]=address+i-r->base;
    }
    for(i=0U;i<width;++i) {
        r=regions[i];
        if(!(r->permissions[offsets[i]]&(writing?2U:1U))) {m->status=5U;return 0;}
        if(!writing && !r->initialized[offsets[i]]) {m->status=6U;return 0;}
    }
    if(m->event_count>=m->event_capacity) {m->status=7U;return 0;}
    return 1;
}
static unsigned long long aether_sparse_memory_load(struct aether_sparse_memory *m,
    unsigned long long space,unsigned long long address,unsigned int width,
    unsigned int big_endian,unsigned long long operation) {
    struct aether_sparse_region *regions[8];unsigned long long offsets[8],value=0ULL;
    unsigned int i,shift;struct aether_sparse_event *event;
    if(!aether_sparse_memory_access(m,space,address,width,0U,regions,offsets)) return 0ULL;
    for(i=0U;i<width;++i) {
        shift=8U*(big_endian?width-1U-i:i);
        value|=((unsigned long long)regions[i]->bytes[offsets[i]])<<shift;
    }
    event=&m->events[m->event_count++];event->operation=operation;event->address=address;
    event->value=value;event->width=width;event->kind=0U;return value;
}
static void aether_sparse_memory_store(struct aether_sparse_memory *m,
    unsigned long long space,unsigned long long address,unsigned int width,unsigned long long value,
    unsigned int big_endian,unsigned long long operation) {
    struct aether_sparse_region *regions[8];unsigned long long offsets[8];
    unsigned int i,shift;struct aether_sparse_event *event;
    if(!aether_sparse_memory_access(m,space,address,width,1U,regions,offsets)) return;
    for(i=0U;i<width;++i) {
        shift=8U*(big_endian?width-1U-i:i);
        regions[i]->bytes[offsets[i]]=(unsigned char)(value>>shift);
        regions[i]->initialized[offsets[i]]=1U;
    }
    event=&m->events[m->event_count++];event->operation=operation;event->address=address;
    event->value=value;event->width=width;event->kind=1U;
}
'''


def reconstruct_high_pcode(data, *, expected_target, expected_address, evidence_sha256,
                           function_name='aether_recovered', memory_model=None, _call_context=None,
                           internal_linkage=False):
    """All-or-abstain reconstruction; never compiles or executes anything."""
    report = dict(schema='ghidra-pcode-c.v1',status='invalid',structured_c_source=None,ctree=None,
        input_bindings=[],return_bits=None,phi_edges=[],errors=[],source_ir_sha256=evidence_sha256,
        target_sha256=expected_target,function_address=expected_address,binary_equivalence_proved=False,
        original_source_recovered=False,abi_recovered=False,limitations=[
            'observed decompiler High P-Code, not original source or binary equivalence',
            'transport signature uses varnode inputs, not recovered source types or ABI',
            'unsigned long long must have exactly 64 value bits; no memory, calls or indirect effects model',
            'C-Tree checks syntax, not compilation or a universal preservation proof'])
    try:
        if type(internal_linkage) is not bool:
            raise ValueError('pcode_c_linkage_invalid')
        if internal_linkage:
            report['linkage']='internal'
        calls=None;call_function=None;effects=False
        if _call_context is not None:
            from aether_re.call_closure import _CallContext
            if type(_call_context) is not _CallContext or memory_model!='bounded-bytes.v2':
                raise ValueError('call_closure_context_not_admitted')
            call_function=_call_context.verify(data,expected_target,expected_address,function_name)
            calls=_call_context
            effects=calls.effects
        if memory_model is not None and memory_model not in ('bounded-bytes.v1','bounded-bytes.v2'):
            raise ValueError('pcode_c_memory_model_invalid')
        checked=analyze_high_pcode(data,expected_target=expected_target,expected_address=expected_address,evidence_sha256=evidence_sha256)
        if not isinstance(function_name,str) or not re.fullmatch(r'aether_[A-Za-z0-9_]{1,80}',function_name):
            raise ValueError('pcode_c_function_name_invalid')
        if checked['summary']['status']!='structurally_valid' or checked['summary']['unresolved_liveins']:
            raise _Unsupported('pcode_c_incomplete_or_unresolved')
        if checked['summary']['unreachable_blocks']:
            raise _Unsupported('pcode_c_unreachable_inventory')
        blocks={b['id']:b for b in data['blocks']};ops={o['id']:o for o in data['operations']}
        variables={v['id']:v for v in data['varnodes']};entry=data['entry_block']
        if blocks[entry]['predecessors']:
            raise _Unsupported('pcode_c_entry_has_predecessors')
        unsupported=sorted({o['opcode'] for o in ops.values()}-(_SUPPORTED|({'LOAD','STORE'} if memory_model else set())|({'CALL'} if calls else set())))
        if unsupported:
            raise _Unsupported('pcode_c_unsupported_opcodes:'+','.join(unsupported))
        if any(v['size'] not in (1,2,4,8) for v in variables.values()):
            raise _Unsupported('pcode_c_unsupported_width')
        # Externally observable storage is not silently converted to a local.
        private_stack={s[0] for s in call_function.stack_slots} if calls else set()
        if any(v.get('persistent') or v['kind'] in ('memory','other') and v.get('definition') or
               v['kind']=='stack' and v.get('definition') and v['id'] not in private_stack for v in variables.values()):
            raise _Unsupported('pcode_c_external_storage')
        if len(variables)>800 or len(ops)>900:
            raise _Unsupported('pcode_c_translation_budget')
        memory_space=None
        memory_helper='aether_sparse_memory' if memory_model=='bounded-bytes.v2' else 'aether_memory'
        if memory_model:
            if function_name.startswith(memory_helper+'_'):
                raise ValueError('pcode_c_memory_reserved_function_name')
            spaces=data['context']['spaces']
            for operation in ops.values():
                if operation['opcode'] in {'LOAD','STORE'}:
                    selector=variables[operation['inputs'][0]]
                    if int(selector['offset'],16) >= 1 << (8*selector['size']):
                        raise _Unsupported('pcode_c_memory_space_selector_width')
            selected={int(variables[o['inputs'][0]]['offset'],16) for o in ops.values() if o['opcode'] in {'LOAD','STORE'}}
            if len(selected)>1:raise _Unsupported('pcode_c_memory_multiple_spaces')
            if selected:
                memory_space=next(s for s in spaces if (s['id'] & 0xffffffff)==next(iter(selected)))
            else:
                memory_space=next(s for s in spaces if s['name']==expected_address.split(':',1)[0])
            if memory_space['kind']!='memory' or memory_space['word_size']!=1:
                raise _Unsupported('pcode_c_memory_space_not_byte_addressable')
            report['runtime_parameters']=[dict(name='aether_memory',c_type='struct '+memory_helper+' *')]
            report['memory_model']=dict(schema=memory_model,endian=data['context']['endian'],space=dict(memory_space),
                memory_reads=sum(o['opcode']=='LOAD' for o in ops.values()),memory_writes=sum(o['opcode']=='STORE' for o in ops.values()),
                empty_block_steps=[b['id'] for b in blocks.values() if not b['operations']],
                step_counting='one per P-Code operation, plus one per visited empty original block',
                byte_limit=1048576,event_limit=4096,step_limit=1000000,abstract_addresses_are_host_pointers=False,
                status_codes={0:'ok',1:'invalid_state',2:'step_budget',3:'space_mismatch',4:'out_of_bounds',5:'permission',6:'uninitialized',7:'trace_budget'},
                permissions=dict(read=1,write=2),caller_hypotheses=['valid nonaliasing runtime state/buffer storage supplied by caller',
                    'one explicit abstract byte-addressable memory region; no recovered process map or ABI',
                    'return value invalid when status is nonzero; null state is an invalid caller precondition'])
            report['limitations']=[text for text in report['limitations'] if 'no memory' not in text]
            report['limitations'].append('explicit bounded byte memory hypothesis; calls/indirect/global persistent storage and complete ABI remain unmodeled')
            if memory_model=='bounded-bytes.v2':
                report['memory_model'].update(region_limit=128,storage_model='ordered_nonoverlapping_regions')
                report['memory_model']['caller_hypotheses'][1]='explicit sparse byte regions; no recovered process map or ABI'
        names={v:f'aether_v{i}' for i,v in enumerate(variables)}
        literal=lambda value:str(value)+'ULL'
        mask=lambda size:literal((1<<(8*size))-1)
        def value(identity):
            var=variables[identity]
            return literal(int(var['offset'],16)&((1<<(8*var['size']))-1)) if var['kind']=='constant' else names[identity]
        inputs=[v for v in variables.values() if v['input']]
        if len(inputs)>64:raise _Unsupported('pcode_c_input_budget')
        input_ids={v['id'] for v in inputs}
        declarations=[f'unsigned long long {names[v]} = 0ULL;' for v in variables if variables[v]['kind']!='constant' and v not in input_ids]
        initial=[]
        if calls:
            arguments=', '.join(str(word)+'ULL' for word in calls.words)
            initial.append(dict(memory_guard='aether_call_entry(aether_calls, '+('1U' if call_function.identity==calls.root_identity else '0U')+', '+arguments+')'))
            if effects:
                initial.append(dict(memory_guard='aether_effect_trace_entry(aether_effects, aether_memory, aether_calls, '+('1U' if call_function.identity==calls.root_identity else '0U')+')'))
        for v in inputs:
            initial.append(f'{names[v["id"]]} &= {mask(v["size"])};')
            report['input_bindings'].append(dict(varnode=v['id'],parameter=names[v['id']],bits=v['size']*8,space=v['space'],offset=v['offset']))
        def expression(op):
            args=[value(i) for i in op['inputs']];sizes=[variables[i]['size'] for i in op['inputs']]
            code=op['opcode'];a=args[0] if args else None;b=args[1] if len(args)>1 else None
            bits=sizes[0]*8 if sizes else 0;sign=literal(1<<(bits-1)) if bits else None
            if code in _BINARY:return f'({a} {_BINARY[code]} {b})'
            if code in _CMP:return f'({a} {_CMP[code]} {b})'
            if code in ('COPY','CAST','INT_ZEXT'):return a
            if code=='INT_NEGATE':return f'(~{a})'
            if code=='INT_2COMP':return f'(0ULL - {a})'
            if code in ('INT_SLESS','INT_SLESSEQUAL'):
                cmp='<' if code=='INT_SLESS' else '<='
                return f'(({a} ^ {sign}) {cmp} ({b} ^ {sign}))'
            if code=='INT_CARRY':return f'(({a} + {b}) < {a})' if bits==64 else f'(({a} + {b}) > {mask(sizes[0])})'
            if code in ('INT_SCARRY','INT_SBORROW'):
                symbol='+' if code=='INT_SCARRY' else '-';equal='==' if symbol=='+' else '!='
                return f'((({a} & {sign}) {equal} ({b} & {sign})) && (((({a} {symbol} {b}) ^ {a}) & {sign}) != 0ULL))'
            if code=='BOOL_NEGATE':return f'(!{a})'
            if code in ('BOOL_XOR','BOOL_AND','BOOL_OR'):
                symbol={'BOOL_XOR':'!=','BOOL_AND':'&&','BOOL_OR':'||'}[code]
                return f'(({a} != 0ULL) {symbol} ({b} != 0ULL))'
            if code=='INT_SEXT':return f'(({a} ^ {sign}) - {sign})'
            if code in ('INT_LEFT','INT_RIGHT'):
                symbol='<<' if code=='INT_LEFT' else '>>'
                return f'({b} >= {bits}ULL ? 0ULL : ({a} {symbol} {b}))'
            if code=='INT_SRIGHT':
                # Both branches guard counts before any C shift is evaluated.
                fill=f'(({a} & {sign}) != 0ULL ? {mask(sizes[0])} : 0ULL)'
                return f'({b} == 0ULL ? {a} : ({b} >= {bits}ULL ? {fill} : (({a} >> {b}) | ({fill} ^ ({fill} >> {b})))))'
            if code=='PIECE':return f'(({a} << {sizes[1]*8}ULL) | {b})'
            if code=='SUBPIECE':return f'({a} >> {int(variables[op["inputs"][1]]["offset"],16)*8}ULL)'
            if code=='PTRADD':return f'({a} + ({b} * {args[2]}))'
            if code=='PTRSUB':return f'({a} + {b})'
            if code=='POPCOUNT':return '('+' + '.join(f'(({a} >> {i}ULL) & 1ULL)' for i in range(bits))+')'
            if code=='LZCOUNT':return '('+' + '.join(f'(({a} >> {i}ULL) == 0ULL)' for i in range(bits))+')'
            raise _Unsupported('pcode_c_unmodeled:'+code)
        if memory_model:
            initial.insert(0,dict(memory_guard=f'{memory_helper}_valid(aether_memory, {literal((1<<memory_space["bits"])-1)})'))
        semantics={};edges=[];routes={};phis={};provenance={}
        operation_indexes={identity:index for index,identity in enumerate(ops)}
        block_indexes={identity:index for index,identity in enumerate(blocks)}
        edge_names=set(blocks);edge_counter=0
        def fresh_edge():
            nonlocal edge_counter
            while True:
                identity=f'aether_edge_{edge_counter}';edge_counter+=1
                if identity not in edge_names:
                    edge_names.add(identity);return identity
        for block in blocks.values():
            items=[ops[i] for i in block['operations']];phi=[];seen_regular=False
            for op in items:
                if op['opcode']=='MULTIEQUAL':
                    if seen_regular:raise ValueError('pcode_c_phi_not_at_entry')
                    phi.append(op)
                else:seen_regular=True
            if phi and not block['predecessors']:raise _Unsupported('pcode_c_phi_without_incoming_edge')
            phis[block['id']]=phi
        for block in blocks.values():
            for slot,successor in enumerate(block['successors']):
                target=successor['block'];destination=target
                if phis[target]:
                    destination=fresh_edge();statements=[];copies=[]
                    for op in phis[target]:
                        temporary=f'aether_phi_{len(declarations)}'
                        declarations.append(f'unsigned long long {temporary} = 0ULL;')
                        statements.append(f'{temporary} = {value(op["inputs"][successor["target_slot"]])};')
                        copies.append(f'{names[op["output"]]} = {temporary};')
                    semantics[destination]=dict(statements=statements+copies,terminator=dict(kind='jump',target=target))
                    report['phi_edges'].append(dict(block=destination,source=block['id'],source_slot=slot,target=target,target_slot=successor['target_slot'],copies=len(copies)))
                    edges.append((destination,target))
                routes[block['id'],slot]=destination;edges.append((block['id'],destination))
        return_sizes=set()
        for block in blocks.values():
            statements=list(initial) if block['id']==entry else []
            if memory_model and not block['operations']:
                tick=memory_helper+'_step(aether_memory)'
                if calls:tick='aether_call_tick(aether_calls) && '+tick
                statements.append(dict(memory_guard=tick))
                if effects:
                    statements.append(dict(memory_guard=f'aether_effect_trace_append(aether_effects, aether_memory, aether_calls, {call_function.number}ULL, {block_indexes[block["id"]]}ULL, 2ULL)'))
            term=None
            for identity in block['operations']:
                op=ops[identity];code=op['opcode'];provenance[identity]=dict(pc=op['sequence']['pc'],block=block['id'])
                if memory_model:
                    tick=memory_helper+'_step(aether_memory)'
                    if calls:tick='aether_call_tick(aether_calls) && '+tick
                    statements.append(dict(memory_guard=tick))
                    if effects:
                        statements.append(dict(memory_guard=f'aether_effect_trace_append(aether_effects, aether_memory, aether_calls, {call_function.number}ULL, {operation_indexes[identity]}ULL, 1ULL)'))
                if code=='MULTIEQUAL':continue
                if code=='CALL' and calls:
                    site=calls.site(call_function.identity,identity);callee=calls.function(site.callee)
                    arguments=[value(v) for v in op['inputs'][1:]]
                    argument_name='aether_call_args_'+str(operation_indexes[identity])
                    if arguments:
                        declarations.append('unsigned long long '+argument_name+'['+str(len(arguments))+'];')
                        statements.extend(argument_name+'['+str(i)+'] = '+argument+';' for i,argument in enumerate(arguments))
                    context_arguments=f'aether_calls, {call_function.number}ULL, {callee.number}ULL, {site.operation_number}ULL'
                    statements.append(dict(memory_guard='aether_call_enter('+context_arguments+', '+(argument_name if arguments else '0')+', '+str(len(arguments))+'ULL)'))
                    invocation=callee.emitted_name+'('+', '.join(['aether_memory','aether_calls']+(['aether_effects'] if effects else [])+[argument_name+'['+str(slot)+']' for slot in site.slots])+')'
                    output=op.get('output')
                    if output is not None:
                        statements.append(f'{names[output]} = ({invocation}) & {mask(variables[output]["size"])};')
                    else:statements.append(invocation+';')
                    returned=names[output] if output is not None else '0ULL'
                    leave='aether_effect_call_finish' if effects else 'aether_call_leave'
                    leave_arguments=context_arguments.replace('aether_calls, ','aether_calls, aether_effects, ',1) if effects else context_arguments
                    statements.append(leave+'('+leave_arguments+', aether_memory->status, '+returned+');')
                    statements.append(dict(memory_guard='!aether_memory->status && !aether_calls->status'+(' && !aether_effects->status' if effects else '')))
                elif code in {'LOAD','STORE'}:
                    width=variables[op['output']]['size'] if code=='LOAD' else variables[op['inputs'][2]]['size']
                    args=f'aether_memory, {value(op["inputs"][0])}, {value(op["inputs"][1])}, {width}U'
                    endian='1U' if data['context']['endian']=='big' else '0U'
                    memory_operation=(call_function.number*1024+operation_indexes[identity]) if effects else operation_indexes[identity]
                    tail=f'{endian}, {literal(memory_operation)}'
                    if code=='LOAD':
                        statements.append(f'{names[op["output"]]} = {memory_helper}_load({args}, {tail});')
                    else:
                        statements.append(f'{memory_helper}_store({args}, {value(op["inputs"][2])}, {tail});')
                    statements.append(dict(memory_guard='!aether_memory->status'))
                elif code=='RETURN':
                    marker=variables[op['inputs'][0]]
                    if marker['kind']!='constant' or int(marker['offset'],16)!=0:
                        raise _Unsupported('pcode_c_unmodeled_return_target_or_halt')
                    if len(op['inputs'])>2:raise _Unsupported('pcode_c_multi_value_return')
                    returned=op['inputs'][1] if len(op['inputs'])==2 else None
                    return_sizes.add(variables[returned]['size']*8 if returned else 0)
                    term=dict(kind='return',value=value(returned) if returned else None)
                elif code=='CBRANCH':
                    term=dict(kind='branch',condition=value(op['inputs'][1]),true=routes[block['id'],1],false=routes[block['id'],0])
                elif code=='BRANCH':term=dict(kind='jump',target=routes[block['id'],0])
                else:
                    output=op['output']
                    statements.append(f'{names[output]} = ({expression(op)}) & {mask(variables[output]["size"])};')
            if term is None:
                if len(block['successors'])!=1:raise _Unsupported('pcode_c_unmodeled_terminal')
                term=dict(kind='jump',target=routes[block['id'],0])
            semantics[block['id']]=dict(statements=statements,terminator=term)
        if len(return_sizes)!=1:raise _Unsupported('pcode_c_absent_or_inconsistent_returns')
        return_bits=next(iter(return_sizes));rtype='unsigned long long' if return_bits else 'void'
        if memory_model:
            # Guards are real CFG branches. Block expression validation stays
            # strict; no hidden return/goto is smuggled into a statement.
            used=set(semantics);counter=0
            def fresh_block():
                nonlocal counter
                while True:
                    identity=f'aether_memory_guard_{counter}';counter+=1
                    if identity not in used:
                        used.add(identity);return identity
            fault=fresh_block();expanded={}
            for identity,body in semantics.items():
                current=identity;pending=[]
                for statement in body['statements']:
                    if isinstance(statement,dict):
                        continuation=fresh_block()
                        expanded[current]=dict(statements=pending,terminator=dict(kind='branch',
                            condition=statement['memory_guard'],true=continuation,false=fault))
                        current=continuation;pending=[]
                    else:pending.append(statement)
                expanded[current]=dict(statements=pending,terminator=body['terminator'])
            expanded[fault]=dict(statements=[],terminator=dict(kind='return',value='0ULL' if return_bits else None))
            if len(expanded)>1024:raise _Unsupported('pcode_c_memory_guard_graph_budget')
            semantics=expanded;edges=[]
            for identity,body in semantics.items():
                term=body['terminator']
                if term['kind']=='jump':edges.append((identity,term['target']))
                elif term['kind']=='branch':edges.extend([(identity,term['false']),(identity,term['true'])])
        parameters=(['struct '+memory_helper+' *aether_memory'] if memory_model else [])+(['struct aether_call_trace *aether_calls'] if calls else [])+(['struct aether_effect_trace *aether_effects'] if effects else [])+['unsigned long long '+names[v['id']] for v in inputs]
        signature=rtype+' '+function_name+'('+(', '.join(parameters) or 'void')+')'
        if internal_linkage or calls and call_function.identity!=calls.root_identity:signature='static '+signature
        tree=structure_control_flow(list(semantics),edges,{},[],entry,block_semantics=semantics,function_signature=signature,declarations=declarations,
            **({'node_budget':512} if effects else {}))
        if tree['status']!='complete':raise _Unsupported('pcode_c_ctree_abstained:'+','.join(tree['errors']))
        runtime=_SPARSE_MEMORY_RUNTIME if memory_model=='bounded-bytes.v2' else _MEMORY_RUNTIME
        source=(runtime+'\n' if memory_model else '')+tree['structured_c_source']
        report.update(status='complete',structured_c_source=source,ctree=tree,
            return_bits=return_bits,function_name=function_name,operation_provenance=provenance,
            source_function_id=checked['graph']['function_id'],word_carrier_bits=64)
        if calls:report['runtime_parameters'].append(dict(name='aether_calls',c_type='struct aether_call_trace *'))
        if effects:report['runtime_parameters'].append(dict(name='aether_effects',c_type='struct aether_effect_trace *'))
    except _Unsupported as exc:
        report.update(status='unsupported',errors=[str(exc)])
    except (ValueError,TypeError,KeyError,IndexError,RecursionError) as exc:
        report.update(status='invalid',errors=[str(exc)[:400] or type(exc).__name__])
    return report
