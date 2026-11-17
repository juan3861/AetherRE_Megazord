"""Derived frame hypotheses: local byte custody, accounting and publication.

Pseudo-source is not original source. A derived model does not certify native
execution, binary equivalence, a native profile, or any release gate.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

from . import evidence
from .frame_request import MAX_FACT_BYTES, read_frame_fact

MAX_FRAME_CASE_BYTES = 8 * 1024 * 1024


def snapshot_frame_fact(path, snapshot_path, *, target_sha256, preflight=None):
    """Preserve original bytes after binding the observed fact to the target."""
    fact, intake = read_frame_fact(path) if preflight is None else deepcopy(preflight)
    if type(fact) is not dict or fact.get('target_sha256') != target_sha256:
        raise ValueError('frame_fact_target_mismatch')
    observed_sha = intake['sha256']
    snapshot_path = Path(snapshot_path)
    copied_sha = evidence.create_verified_snapshot(
        Path(path), snapshot_path, expected_sha256=observed_sha, max_bytes=MAX_FACT_BYTES)
    if copied_sha != observed_sha:
        raise ValueError('frame_fact_snapshot_digest_mismatch')
    snap_fact, snap_intake = read_frame_fact(snapshot_path)
    if snap_intake['sha256'] != observed_sha or snap_fact != fact:
        raise ValueError('frame_fact_snapshot_changed')
    receipt = deepcopy(intake)
    receipt.update(snapshot_path=str(snapshot_path), sha256=copied_sha,
                   bytes=snap_intake['bytes'], native_fact_verified=False)
    return deepcopy(snap_fact), receipt


def _frame_case(target_sha256,metadata):
    result = dict(
        schema='derived-frame-case.v1', target_sha256=target_sha256,
        status='backend_unavailable', program_kind='derived_model',
        requested_programs=1, attempted_programs=0, derived_programs=0,
        refused_programs=0, exported_total_functions=0, program=None,
        **deepcopy(metadata), target_executed=False,
        binary_equivalence=False, original_source=False, native_profile=False,
        binary_equivalence_proved=False, original_source_recovered=False,
        abi_recovered=False, native_frame_fact_verified=False, native_admitted=False,
        limitations=[
            'pseudo-source is not original source',
            'supplied frame facts are hypotheses, not verified native relations',
            'derived model does not prove binary equivalence or native profile admission',
        ])
    return result


def _finish_frame_case(exported,*,target_sha256,profile,result,supported_profiles,select,frame_runtime=None):
    if exported is not None:
        if exported.target_sha256 != target_sha256:
            raise ValueError('frame_export_target_mismatch')
        result.update(exported_total_functions=exported.total_functions,
                      backend_status=exported.status,
                      worker_execution=deepcopy(exported.worker_execution))
    if profile not in supported_profiles:
        result['status'] = 'unsupported_profile'
        return result
    if exported is None:
        return result
    if not exported.success:
        result.update(status='backend_failed', error_message=exported.error_message)
        return result
    result['attempted_programs'] = 1
    try:
        program = select()
    except ValueError as error:
        result.update(status='refused', refused_programs=1, error_code=400,
                      error_message=str(error)[:400])
        return result
    result['program'] = deepcopy(program)
    from .frame_request import frame_program_succeeded
    if frame_program_succeeded(program,frame_runtime):
        result.update(status=program['status'], derived_programs=1)
    else:
        result.update(status='refused', refused_programs=1)
    return result


def build_frame_case(exported, *, target_sha256, selector, fact, intake, profile,frame_runtime=None):
    """Account for one requested conditional model, independently of callees."""
    from .frame_request import validate_frame_runtime_request
    validate_frame_runtime_request(frame_runtime,selector,None)
    options={} if frame_runtime is None else dict(frame_runtime=frame_runtime)
    return _finish_frame_case(exported,target_sha256=target_sha256,profile=profile,frame_runtime=frame_runtime,
        result=_frame_case(target_sha256,dict(fact_intake=intake)),
        supported_profiles={'native-pe','native-elf','macho'},select=lambda:exported.select_frame_program(selector,fact,**options))


def build_observed_frame_case(exported,*,target_sha256,selector,inputs,object_bytes,profile,frame_runtime=None):
    """Observe a caller prefix while retaining requested-extent/native limits."""
    from .frame_request import validate_frame_runtime_request
    validate_frame_runtime_request(frame_runtime,None,selector)
    options={} if frame_runtime is None else dict(frame_runtime=frame_runtime)
    result=_frame_case(target_sha256,dict(native_frame_input_receipt=inputs['receipt']))
    result['export_artifact_dir']=getattr(exported,'artifact_dir',None)
    result['export_artifact_hashes']=deepcopy(getattr(exported,'artifact_hashes',{}))
    result['limitations'][1]='native address prefix depends on declared layout; object extent remains requested'
    return _finish_frame_case(exported,target_sha256=target_sha256,profile=profile,result=result,frame_runtime=frame_runtime,
        supported_profiles={'native-pe'},select=lambda:exported.select_observed_frame_program(selector,
            target_bytes=inputs['target_bytes'],language_sources=inputs['language_sources'],object_bytes=object_bytes,input_receipt=inputs['receipt'],**options))


def publish_frame_case(result, path):
    """Publish a bounded new JSON body; return its separate hash receipt."""
    from .ghidra_headless_bridge import publish_export_output

    body = deepcopy(result)
    content = json.dumps(body, ensure_ascii=False, allow_nan=False, sort_keys=True,
                         separators=(',', ':')) + '\n'
    raw = content.encode('utf-8', errors='strict')
    if len(raw) > MAX_FRAME_CASE_BYTES:
        raise ValueError('frame_case_publication_budget_exceeded')
    expected_sha = hashlib.sha256(raw).hexdigest()
    path = Path(path)
    published_sha = publish_export_output(path, content)
    if published_sha != expected_sha or evidence.sha256_file(path) != expected_sha:
        raise ValueError('frame_case_publication_digest_mismatch')
    body['publication'] = dict(path=str(path), sha256=expected_sha, bytes=len(raw))
    return body
