"""Build an explicitly derived bounded frame program, without native admission.

Original IR is immutable. A supplied frame fact remains an explicit hypothesis.
Generated C executes only when a caller separately compiles/invokes the model.
"""
from __future__ import annotations
import re
from aether_re.frame_derivation import derive_frame_program as _derive, _digest
from aether_re.frame_usage import prove_frame_usage
from aether_re.frame_conservation import check_frame_transport
from aether_re.frame_runtime import FRAME_RUNTIME
from aether_re.ghidra_pcode_c import reconstruct_high_pcode


def build_frame_program(root, callee, frame_fact, *, object_base=0x100000, function_name='aether_frame_entry'):
    """Return a derived-model report; failures never publish executable C."""
    report = dict(schema='conditional-frame-program.v1', status='invalid', program_kind='derived_model',
                  structured_c_source=None, errors=[], native_frame_fact_verified=False,
                  production_frame_profile_admitted=False, abi_recovered=False,
                  binary_equivalence_proved=False, original_source_recovered=False,
                  limitations=['distinct derived program under caller-supplied frame hypothesis',
                      'trusted nonaliasing runtime metadata/buffers; no callback descriptor fencing',
                      'no recovered native ABI, call trace or original source',
                      'no native/IR fidelity or production call-profile admission'])
    try:
        if (type(function_name) is not str or not re.fullmatch(r'aether_[A-Za-z0-9_]{1,60}', function_name)
                or function_name == 'aether_frame_body' or function_name.startswith(('aether_sparse_memory_', 'aether_frame_enter', 'aether_frame_leave'))):
            raise ValueError('frame_program_function_name')
        usage = prove_frame_usage(root=root, callees=[callee], frame_fact=frame_fact)
        packet = _derive(root['pcode_ir'], callee, frame_fact, object_base=object_base)
        links = check_frame_transport(root, callee, frame_fact, packet, usage, object_base=object_base)
        ir = packet['derived_ir']
        emitted = reconstruct_high_pcode(ir, expected_target=ir['target_sha256'], expected_address=ir['function_address'],
            evidence_sha256=_digest(ir), function_name='aether_frame_body', memory_model='bounded-bytes.v2', internal_linkage=True)
        if emitted['status'] != 'complete':
            raise ValueError('frame_program_emitter_refused:' + ','.join(emitted['errors']))
        extent = packet['provenance']['frame']['object_bytes']
        bindings = emitted['input_bindings']; bits = emitted['return_bits']
        rtype = 'unsigned long long' if bits else 'void'
        parameters = ['struct aether_sparse_memory *aether_memory'] + ['unsigned long long ' + item['parameter'] for item in bindings]
        arguments = ', '.join(['aether_memory'] + [item['parameter'] for item in bindings])
        exit_stmt = 'return 0ULL;' if bits else 'return;'
        lines = [rtype + ' ' + function_name + '(' + ', '.join(parameters) + ') {',
            '    struct aether_frame_scope aether_scope = {0};',
            f'    unsigned char aether_bytes[{extent}] = {{0}};',
            f'    unsigned char aether_permissions[{extent}];',
            f'    unsigned char aether_initialized[{extent}] = {{0}};',
            '    unsigned long long aether_index;',
            *(['    unsigned long long aether_result;'] if bits else []),
            f'    if (!aether_memory || aether_memory->status) {{ {exit_stmt} }}',
            f'    for(aether_index=0ULL;aether_index<{extent}ULL;++aether_index) aether_permissions[aether_index]=3U;',
            f'    if (!aether_frame_enter(&aether_scope, aether_memory, {object_base}ULL, {extent}ULL, aether_bytes, aether_permissions, aether_initialized)) {{',
            '        if (!aether_memory->status) aether_memory->status=1U;',
            '        ' + exit_stmt, '    }',
            ('    aether_result = ' if bits else '    ') + 'aether_frame_body(' + arguments + ');',
            '    if (!aether_frame_leave(&aether_scope) && !aether_memory->status) aether_memory->status=1U;',
            ('    return aether_memory->status ? 0ULL : aether_result;' if bits else '    return;'), '}']
        source = emitted['structured_c_source'] + '\n' + FRAME_RUNTIME + '\n' + '\n'.join(lines) + '\n'
        if len(source.encode('utf-8')) > 1048576:
            raise ValueError('frame_program_output_budget')
        report.update(status='complete', structured_c_source=source, derived_ir=ir,
            provenance=packet['provenance'], usage=usage, memory_links=links, emitted=emitted,
            frame=packet['provenance']['frame'], input_bindings=bindings, return_bits=bits,
            function_name=function_name, source_ir_sha256=root['ir_analysis']['source_ir_sha256'],
            target_sha256=ir['target_sha256'], function_address=ir['function_address'])
    except (ValueError, KeyError, TypeError, IndexError, AttributeError, StopIteration, RecursionError) as error:
        report['errors'] = [str(error) if isinstance(error, ValueError) else 'frame_program_envelope']
    return report
