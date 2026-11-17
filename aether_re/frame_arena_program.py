"""Conditional invocation arenas over validated relocatable IR models.

Pseudo-source is not original source. Caller-owned C metadata must be valid,
nonaliasing and exclusively owned; descriptor checks do not sandbox callbacks.
"""
import re
from aether_re.frame_relocation import emit_relocatable_frame_body
from aether_re.frame_arena_runtime import FRAME_ARENA_RUNTIME

def build_frame_arena_program(root,callee,fact,*,function_name='aether_model_arena_entry'):
    if type(function_name) is not str or not re.fullmatch(r'aether_model_[A-Za-z0-9_]{1,48}',function_name):
        raise ValueError('frame_arena_program_function_name')
    body=emit_relocatable_frame_body(root,callee,fact);emitted=body['emitted']
    ambient=fact['ambient_varnode'];delta=fact['entry_rsp_offset'];extent=fact['requested_object_bytes']
    scalars=[p['parameter'] for p in emitted['input_bindings'] if p['varnode']!=ambient]
    arguments=['aether_memory']+['aether_entry' if p['varnode']==ambient else p['parameter'] for p in emitted['input_bindings']]
    bits=emitted['return_bits'];rtype='unsigned long long' if bits else 'void';exit_stmt='return 0ULL;' if bits else 'return;'
    parameters=['struct aether_arena_context *aether_arena']+['unsigned long long '+p for p in scalars]
    lines=[rtype+' '+function_name+'('+', '.join(parameters)+') {',
        '    struct aether_arena_scope aether_scope;',
        '    struct aether_sparse_memory *aether_memory;',
        f'    unsigned char aether_bytes[{extent}],aether_permissions[{extent}],aether_initialized[{extent}];',
        '    unsigned long long aether_i,aether_token,aether_entry;',
        *(['    unsigned long long aether_result=0ULL;'] if bits else []),
        '    if(!aether_arena || !aether_arena->memory) { '+exit_stmt+' }',
        '    aether_memory=aether_arena->memory;',
        '    if(aether_memory->status) { '+exit_stmt+' }',
        '    aether_scope.frame.active=0U;aether_scope.arena=0;',
        f'    for(aether_i=0ULL;aether_i<{extent}ULL;++aether_i) {{aether_bytes[aether_i]=0U;aether_permissions[aether_i]=3U;aether_initialized[aether_i]=0U;}}',
        f'    if(!aether_arena_enter(aether_arena,&aether_scope,{extent}ULL,aether_bytes,aether_permissions,aether_initialized)) {{ '+exit_stmt+' }',
        '    aether_token=aether_scope.token;']
    if delta>=0:
        lines += [f'    if(aether_scope.base<{delta}ULL) {{aether_memory->status=1U;goto aether_cleanup;}}',
                  f'    aether_entry=aether_scope.base-{delta}ULL;']
    else:
        lines += [f'    if(aether_scope.base>ULLONG_MAX-{abs(delta)}ULL) {{aether_memory->status=1U;goto aether_cleanup;}}',
                  f'    aether_entry=aether_scope.base+{abs(delta)}ULL;']
    lines += ['    '+('aether_result=' if bits else '')+'aether_relocatable_body('+', '.join(arguments)+');',
        '    aether_cleanup:',
        '    if(!aether_arena_leave(aether_arena,&aether_scope,aether_token) && !aether_memory->status)aether_memory->status=1U;',
        '    '+('return aether_memory->status?0ULL:aether_result;' if bits else 'return;'),'}']
    source=emitted['structured_c_source']+'\n'+FRAME_ARENA_RUNTIME+'\n'+'\n'.join(lines)+'\n'
    if len(source.encode('utf-8'))>1048576:raise ValueError('frame_arena_program_output_budget')
    return dict(schema='conditional-arena-program.v1',status='conditional_model',program_kind='derived_model',body=body,structured_c_source=source,
        function_name=function_name,parameters=scalars,runtime_placement_domain_guarded=True,
        invocation_tokens_included=True,descriptor_shape_checks_included=True,caller_valid_nonaliasing_metadata_required=True,
        native_frame_fact_verified=False,production_admission=False,abi_recovered=False,binary_equivalence_proved=False,
        original_source_recovered=False,lifetime_escape_proved=False,arbitrary_callback_isolation=False)
