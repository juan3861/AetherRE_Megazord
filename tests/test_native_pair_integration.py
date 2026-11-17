import copy
import hashlib
import json
from argparse import Namespace
from dataclasses import replace
from pathlib import Path

import pytest
from test_native_leaf_data import inputs


def loaded_pair(tmp_path, monkeypatch):
    from aether_re.ghidra_headless_bridge import _load_export, GhidraDecompilationResult
    import aether_re.ghidra_headless_bridge as bridge
    from aether_re.native_frame_request import read_native_frame_inputs
    raw, root, callee, language = inputs()
    export = tmp_path / 'export'
    export.mkdir()
    (export / 'ir').mkdir()
    (export / 'functions').mkdir()
    rows = []
    for index, (role, info) in enumerate((('root', root), ('callee', callee))):
        irfile = f'ir/ir{index}.json'
        sourcefile = f'functions/f{index}.c'
        (export / irfile).write_text(json.dumps(info['pcode_ir']))
        (export / sourcefile).write_text('unsigned long long source(void){return 0;}')
        rows.append(dict(name=role + '_native', address=info['pcode_ir']['function_address'],
            params=len(info['high_parameter_observation']['parameters']), return_type='ulonglong',
            signature_source='ANALYSIS', signature='ulonglong f(void)', success=True,
            source_file=sourcefile, ir_file=irfile, high_parameter_observation=info['high_parameter_observation']))
    target_sha = hashlib.sha256(raw).hexdigest()
    summary = dict(schema='aetherre-ghidra-export.v2', target_sha256=target_sha, complete=True,
        total_functions=2, decompiled_functions=2, failed_functions=0, functions=rows,
        type_policy=dict(mode='observed_program_types', external_types_injected=False, legacy_type_injection_requested=False))
    (export / 'decompilation_summary.json').write_text(json.dumps(summary))
    functions, *_ = _load_export(export, target_sha)
    result = GhidraDecompilationResult('not-executed', True, 2, 2, functions, '', '', 0,
        target_sha256=target_sha, status='complete')
    target = tmp_path / 'owned.dll'
    target.write_bytes(raw)
    directory = tmp_path / 'language'
    directory.mkdir()
    for name, content in language.items():
        (directory / name).write_bytes(content)
    packet = read_native_frame_inputs(target, directory)
    calls = []

    class Backend:
        def decompile_binary(self, path, **options):
            assert Path(path).read_bytes() == raw
            calls.append(path)
            return result

    monkeypatch.setattr(bridge, 'GhidraHeadlessBridge', Backend)
    return result, packet, target, directory, calls


def observe(result, packet, runtime=None):
    return result.select_observed_frame_program('root_native', target_bytes=packet['target_bytes'],
        language_sources=packet['language_sources'], object_bytes=16, frame_runtime=runtime,
        input_receipt=packet['receipt'])


def assert_witness(program):
    witness = program['native_pair_data_observation']
    assert witness['status'] == 'observed'
    assert witness['ordered_data_events_equal'] and witness['return_data_equal']
    body = {key: value for key, value in witness.items() if key != 'witness_sha256'}
    encoded = json.dumps(body, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()
    assert hashlib.sha256(encoded).hexdigest() == witness['witness_sha256']
    assert not witness['binary_equivalence_proved'] and not witness['native_profile_admitted']
    assert witness['selected_functions'] == program['selected_functions']
    return witness


@pytest.mark.parametrize('runtime', [None, 'invocation-arena.v1'])
@pytest.mark.parametrize('route', ['reader', 'cli', 'mcp', 'universal'])
def test_four_routes_publish_same_witness(tmp_path, monkeypatch, capsys, runtime, route):
    from megazord import cmd_ghidra_decompile
    from aether_re.mcp_server import AetherMcpDispatcher
    from aether_re.pipeline import CasePolicy, run_universal_case
    result, packet, target, directory, calls = loaded_pair(tmp_path, monkeypatch)
    expected = assert_witness(observe(result, packet, runtime))
    options = dict(observe_frame_function='root_native', frame_object_bytes=16,
        frame_language_dir=str(directory), frame_runtime=runtime)
    if route == 'reader':
        program = observe(result, packet, runtime)
    elif route == 'cli':
        assert cmd_ghidra_decompile(Namespace(target=str(target), out=None, **options)) == 0
        program = json.loads(capsys.readouterr().out)['derived_frame_program']
    elif route == 'mcp':
        payload = AetherMcpDispatcher.handle_ghidra_decompile(str(target), **options)
        assert payload['success']
        program = payload['derived_frame_program']
    else:
        policy = replace(CasePolicy.static_only(), **options)
        report = run_universal_case(target, tmp_path / 'case', policy)
        assert report.derived_frame_program['derived_programs'] == 1
        program = report.derived_frame_program['program']
    assert json.loads(json.dumps(assert_witness(program))) == json.loads(json.dumps(expected))
    assert program['status'] == ('complete' if runtime is None else 'conditional_model')
    assert len(calls) == (0 if route == 'reader' else 1)


@pytest.mark.parametrize('part', ['root_ir', 'callee_ir', 'root_high', 'callee_high', 'storage', 'callee_id', 'target', 'language_receipt'])
def test_invalid_identity_and_custody_cannot_publish_positive(tmp_path, monkeypatch, part):
    result, packet, *_ = loaded_pair(tmp_path, monkeypatch)
    root = result.get_unique_function('root_native')
    callee = result.get_unique_function('callee_native')
    if part.endswith('_ir'):
        info = root if part.startswith('root') else callee
        info.pcode_ir['operations'][0]['sequence']['time'] += 1
    elif part.endswith('_high'):
        info = root if part.startswith('root') else callee
        info.high_parameter_observation['parameters'][0]['name'] = 'drift'
    elif part == 'storage':
        callee.storage_observation = {}
    elif part == 'callee_id':
        callee.function_id = 'bad'
    elif part == 'target':
        packet['target_bytes'] = packet['target_bytes'][:-1] + b'!'
    else:
        packet['receipt']['language_sources']['ia.sinc']['sha256'] = '0' * 64
    with pytest.raises(ValueError):
        observe(result, packet)


@pytest.mark.parametrize('reason', ['unproved_call_clobber_use', 'aligned_object_store', 'stack_object_lifetime', 'unsupported_instruction'])
def test_projection_refusal_is_separate_from_model(tmp_path, monkeypatch, reason):
    from aether_re import native_caller_data
    result, packet, *_ = loaded_pair(tmp_path, monkeypatch)

    def refuse(**options):
        raise ValueError('native_caller_' + reason)

    monkeypatch.setattr(native_caller_data, 'observe_pair_data_effects', refuse)
    program = observe(result, packet)
    assert program['status'] == 'complete'
    witness = program['native_pair_data_observation']
    assert witness['status'] == 'refused' and witness['error_message'].endswith(reason)
    assert witness['ordered_data_events_equal'] is False and witness['return_data_equal'] is False
    assert not witness['binary_equivalence_proved'] and not witness['production_admission']


@pytest.mark.parametrize('runtime', [None, 'invocation-arena.v1'])
@pytest.mark.parametrize('observed', [False, True])
def test_derived_model_and_arena_body_unchanged(tmp_path, monkeypatch, runtime, observed):
    result, packet, *_ = loaded_pair(tmp_path, monkeypatch)
    before = copy.deepcopy(result)
    report = observe(result, packet, runtime)
    fact = report['native_address_observation']
    fixed = result.select_frame_program('root_native', fact, frame_runtime=runtime)
    assert 'native_pair_data_observation' not in fixed
    assert report['structured_c_source'] == fixed['structured_c_source']
    program = report if observed else fixed
    assert ('native_pair_data_observation' in program) == observed
    assert result == before


def test_refusal_never_serializes_exception_suffix(tmp_path, monkeypatch):
    from aether_re import native_caller_data
    result, packet, *_ = loaded_pair(tmp_path, monkeypatch)
    def refuse(**options):
        raise ValueError('native_caller_unproved_call_clobber_use: PRIVATE_PATH_OR_TOKEN')
    monkeypatch.setattr(native_caller_data, 'observe_pair_data_effects', refuse)
    witness = observe(result, packet)['native_pair_data_observation']
    assert witness['status'] == 'refused'
    assert 'PRIVATE_PATH_OR_TOKEN' not in json.dumps(witness)


@pytest.mark.parametrize('error', ['native_leaf_target_identity', 'native_frame_input_packet_digest_mismatch'])
def test_inner_identity_or_custody_error_propagates(tmp_path, monkeypatch, error):
    from aether_re import native_caller_data
    result, packet, *_ = loaded_pair(tmp_path, monkeypatch)
    def refuse(**options):
        raise ValueError(error)
    monkeypatch.setattr(native_caller_data, 'observe_pair_data_effects', refuse)
    with pytest.raises(ValueError, match=error):
        observe(result, packet)


@pytest.mark.parametrize('conflicting', [False, True])
def test_incomplete_layout_refuses_projection_but_conflict_rejects_input(tmp_path, monkeypatch, conflicting):
    result, packet, *_ = loaded_pair(tmp_path, monkeypatch)
    raw = packet['language_sources']['ia.sinc']
    raw = raw.replace(b'R8 R9', b'R9 R8') if conflicting else raw.split(b'\n')[0]
    packet['language_sources']['ia.sinc'] = raw
    item = packet['receipt']['language_sources']['ia.sinc']
    item.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    if conflicting:
        with pytest.raises(ValueError, match='native_leaf_register_layout'):
            observe(result, packet)
    else:
        program = observe(result, packet)
        assert program['status'] == 'complete'
        assert program['native_pair_data_observation']['status'] == 'refused'
