"""Bounded strict intake for an explicit conditional frame hypothesis."""
from __future__ import annotations
import hashlib,json,math,os,stat
from pathlib import Path

MAX_FACT_BYTES=65536


def validate_frame_runtime_request(runtime,derive_selector=None,observe_selector=None):
    if runtime is None:return
    if type(runtime) is not str or runtime!='invocation-arena.v1':
        raise ValueError('frame_runtime_invalid')
    selectors=[value for value in (derive_selector,observe_selector) if value is not None]
    if (len(selectors)!=1 or type(selectors[0]) is not str or not selectors[0].strip()
            or len(selectors[0])>4096 or '\0' in selectors[0]):
        raise ValueError('frame_runtime_requires_one_frame_route')


def frame_program_succeeded(program,runtime=None):
    if runtime is None:return program.get('status')=='complete'
    return (runtime=='invocation-arena.v1' and program.get('schema')=='conditional-arena-program.v1'
        and program.get('status')=='conditional_model' and program.get('frame_runtime')==runtime
        and program.get('runtime_placement_domain_guarded') is True
        and program.get('invocation_tokens_included') is True
        and program.get('production_admission') is False and program.get('binary_equivalence_proved') is False)


def validate_frame_request(selector,fact_path,**options):
    if selector is None and fact_path is None:
        return
    if (type(selector) is not str or not selector.strip() or len(selector)>4096
            or not isinstance(fact_path,(str,Path)) or not 1<=len(str(fact_path))<=32768 or not str(fact_path).strip()):
        raise ValueError('frame_request_requires_selector_and_fact')
    for name in ('reconstruct_function','memory_model','memory_derivation','call_model','debug_pdb','dia_helper','dia_dll'):
        if options.get(name) is not None:
            raise ValueError('frame_request_option_conflict:'+name)
    if options.get('out') is not None and Path(options['out']).suffix.lower()=='.c':
        raise ValueError('frame_request_requires_json_output')


def _object(pairs):
    result={}
    for name,value in pairs:
        if name in result:raise ValueError('frame_fact_duplicate_key')
        result[name]=value
    return result


def _ordinary(info):
    return (stat.S_ISREG(info.st_mode) and info.st_nlink==1
            and not getattr(info,'st_file_attributes',0)&0x400)


def _finite_float(raw):
    value=float(raw)
    if not math.isfinite(value):raise ValueError('frame_fact_nonfinite')
    return value


def read_frame_fact(path):
    """Hash observed bytes; this does not verify any claimed native relation."""
    path=Path(path);before=path.lstat()
    if not _ordinary(before) or before.st_size>MAX_FACT_BYTES:
        raise ValueError('frame_fact_file_or_budget')
    with path.open('rb') as handle:
        opened=os.fstat(handle.fileno());raw=handle.read(MAX_FACT_BYTES+1);after=os.fstat(handle.fileno())
    final=path.lstat()
    key=lambda info:(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns)
    if (len(raw)>MAX_FACT_BYTES or not all(_ordinary(info) for info in (opened,after,final))
            or len(raw)!=after.st_size or not key(before)==key(opened)==key(after)==key(final)):
        raise ValueError('frame_fact_changed_or_budget')
    try:
        value=json.loads(raw.decode('utf-8',errors='strict'),object_pairs_hook=_object,
            parse_float=_finite_float,
            parse_constant=lambda _:(_ for _ in ()).throw(ValueError('frame_fact_nonfinite')))
    except (UnicodeDecodeError,json.JSONDecodeError,RecursionError) as error:
        raise ValueError('frame_fact_json_invalid') from error
    if type(value) is not dict:raise ValueError('frame_fact_object_required')
    return value,dict(schema='frame-fact-intake.v1',sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw),
                      native_fact_verified=False,scope='observed local hypothesis bytes')
