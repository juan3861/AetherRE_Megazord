"""Leitura opcional e explícita de símbolos PDB via DIA SDK no Windows.

O módulo não executa o binário analisado. Ele chama somente um helper DIA
fornecido pelo operador, registra hashes dos componentes e falha fechado se
helper/DLL/PDB não puderem ser verificados.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import shutil
import uuid
from pathlib import Path
from typing import Any

from aether_re.process import run_bounded
from aether_re.evidence import create_verified_snapshot, _has_link_or_reparse_component
from aether_re.pe_debug import parse_pe_codeview

SCHEMA = "re-megazord-dia-symbols.v1"
_MAX_OUTPUT = 64 * 1024 * 1024
_RAW_FIELDS={'schema','status','capabilities','machine','guid','age','symbols','count','truncated','enumeration_complete',
    'types','type_count','type_edges','types_complete'}


def _payload_digest(raw):
    return hashlib.sha256(json.dumps({k:v for k,v in raw.items() if k in _RAW_FIELDS},sort_keys=True,
        separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')).hexdigest()


def _report_digest(report):
    return hashlib.sha256(json.dumps(dict(payload=_payload_digest(report),binding=report.get('binding'),
        digests={k:report.get(k) for k in ('binary_sha256','pdb_sha256','helper_sha256','dia_dll_sha256')}),
        sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')).hexdigest()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _regular(path: Path) -> bool:
    try:
        return path.is_file() and not _has_link_or_reparse_component(path) and path.stat().st_nlink == 1
    except OSError:
        return False


def _unavailable(code: str, *, pdb_path: Path, helper_path: Path, dia_dll: Path, detail: str = "") -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "status": "unavailable",
        "code": code,
        "pdb": str(pdb_path),
        "helper": str(helper_path),
        "dia_dll": str(dia_dll),
        "detail": detail,
        "symbols": [],
        "count": 0,
        "truncated": False,
        "executed_target": False,
    }


def _type_inventory(raw, symbols, capabilities):
    fields={'types','type_count','type_edges','types_complete'}
    if 'function_types' not in capabilities:
        if fields & raw.keys() or any('function_type' in s for s in symbols):raise ValueError('unclaimed_type_payload')
        return dict(status='unavailable',functions_total=len(symbols),functions_with_signature=0,types=0)
    types=raw.get('types')
    if (not isinstance(types,list) or len(types)>8192 or type(raw.get('type_count')) is not int or raw['type_count']!=len(types)
        or type(raw.get('type_edges')) is not int or not 0<=raw['type_edges']<=65536 or type(raw.get('types_complete')) is not bool):
        raise ValueError('type_inventory_invalid')
    inventory={}
    integer=lambda x: type(x) is int and 0<x<2**32
    for node in types:
        if not isinstance(node,dict) or not integer(node.get('id')) or node['id'] in inventory:raise ValueError('type_id_invalid')
        if set(node)!={'id','tag','name','length','base_type','count','calling_convention','target','parameters','parameters_complete','opaque_layout'}:raise ValueError('type_fields_invalid')
        if (not isinstance(node['name'],str) or len(node['name'])>32768 or type(node['parameters_complete']) is not bool
            or type(node['opaque_layout']) is not bool or not isinstance(node['parameters'],list) or len(node['parameters'])>512):raise ValueError('type_properties_invalid')
        for key in ('tag','length','base_type','count','calling_convention'):
            value=node[key]
            if value is not None and (type(value) is not int or not 0<=value<(2**64 if key=='length' else 2**32)):raise ValueError('type_property_range_invalid')
        if node['tag'] is not None and node['tag']>43:raise ValueError('type_tag_invalid')
        if node['base_type'] is not None and node['base_type'] not in {0,1,2,3,6,7,8,9,10,13,14,25,26,27,28,29,30,31,32,33,34,35}:raise ValueError('basic_type_enum_invalid')
        if node['tag']==16:
            if node['target'] is not None or node['parameters']:raise ValueError('base_type_shape_invalid')
            if raw['types_complete'] and (node['base_type'] is None or node['length'] is None):raise ValueError('base_type_incomplete_claim')
        if node['opaque_layout']!=(node['tag']==11):raise ValueError('type_layout_claim_invalid')
        inventory[node['id']]=node
    references=0;signatures=0
    for node in types:
        refs=[node['target'],*node['parameters']]
        for ref in refs:
            if ref is not None:
                if not integer(ref) or ref not in inventory:raise ValueError('type_reference_missing')
                references+=1
        if node['tag']==13:
            if node['parameters_complete'] and node['count']!=len(node['parameters']):raise ValueError('type_parameter_count_invalid')
            if raw['types_complete'] and (not node['parameters_complete'] or any(p is None for p in node['parameters'])):raise ValueError('type_parameter_completeness_invalid')
            if node['target'] is not None and inventory[node['target']]['tag']==13:raise ValueError('function_returns_function_type')
        elif node['parameters']:raise ValueError('type_parameters_on_nonfunction')
        if raw['types_complete'] and (node['tag'] is None or node['tag'] in {12,13,14,15,17} and node['target'] is None):raise ValueError('type_incomplete_claim')
    for symbol in symbols:
        identity=symbol.get('function_type')
        if identity is None:
            if raw['types_complete']:raise ValueError('function_type_missing')
        else:
            if not integer(identity) or identity not in inventory or inventory[identity]['tag']!=13:raise ValueError('function_type_invalid')
            references+=1;signatures+=1
    if references>raw['type_edges'] or raw['types_complete'] and references!=raw['type_edges']:raise ValueError('type_edge_count_invalid')
    return dict(status='observed_complete' if raw['types_complete'] else 'partial',functions_total=len(symbols),
        functions_with_signature=signatures,types=len(types),opaque_layout_types=sum(t['opaque_layout'] for t in types))


def extract_pdb_symbols(
    pdb_path: Path,
    *,
    helper_path: Path,
    dia_dll: Path,
    timeout: float = 90.0,
    max_symbols: int = 50_000,
    memory_limit_mb: int = 512,
    binary_path: Path | None = None,
    temp_work_dir: Path | None = None,
) -> dict[str, Any]:
    """Extract function symbols from one PDB using an explicit DIA helper.

    The helper is treated as an analysis tool, never as the target. Its JSON
    output is bounded and authenticated by the helper/DIA/PDB hashes.
    """
    pdb_path = Path(pdb_path).absolute()
    helper_path = Path(helper_path).absolute()
    dia_dll = Path(dia_dll).absolute()
    binary_path = Path(binary_path).absolute() if binary_path is not None else None
    if os.name != "nt":
        return _unavailable("windows_required", pdb_path=pdb_path, helper_path=helper_path, dia_dll=dia_dll)
    if not _regular(pdb_path):
        return _unavailable("pdb_invalid", pdb_path=pdb_path, helper_path=helper_path, dia_dll=dia_dll)
    if not _regular(helper_path):
        return _unavailable("helper_invalid", pdb_path=pdb_path, helper_path=helper_path, dia_dll=dia_dll)
    if not _regular(dia_dll):
        return _unavailable("dia_dll_invalid", pdb_path=pdb_path, helper_path=helper_path, dia_dll=dia_dll)
    if isinstance(max_symbols, bool) or not isinstance(max_symbols, int) or not 1 <= max_symbols <= 1_000_000:
        return _unavailable("max_symbols_invalid", pdb_path=pdb_path, helper_path=helper_path, dia_dll=dia_dll)
    if (type(timeout) not in (int,float) or not 0 < timeout <= 600
            or type(memory_limit_mb) is not int or not 128<=memory_limit_mb<=8192):
        return _unavailable('worker_budget_invalid',pdb_path=pdb_path,helper_path=helper_path,dia_dll=dia_dll)
    if binary_path is not None and not _regular(binary_path):
        return _unavailable('binary_invalid',pdb_path=pdb_path,helper_path=helper_path,dia_dll=dia_dll)
    metadata={}
    def failed(code,detail=''):
        return {**_unavailable(code,pdb_path=pdb_path,helper_path=helper_path,dia_dll=dia_dll,detail=detail),**metadata}
    context=None
    try:
        required=sum(p.stat().st_size for p in (pdb_path,helper_path,dia_dll,*([binary_path] if binary_path else [])))+128*1024*1024
        candidates=[Path(temp_work_dir)] if temp_work_dir is not None else [Path(tempfile.gettempdir()),Path.home()/'.aetherre'/'tmp']
        parent=None
        for candidate in candidates:
            existing=candidate
            while not existing.exists() and existing!=existing.parent:existing=existing.parent
            if shutil.disk_usage(existing).free>=required:
                candidate.mkdir(parents=True,exist_ok=True);parent=candidate;break
        if parent is None:return failed('snapshot_disk_reserve_unavailable')
        if temp_work_dir is None:
            context=tempfile.TemporaryDirectory(prefix='aether-dia-',dir=parent);folder=Path(context.name)
        else:
            folder=Path(tempfile.mkdtemp(prefix='run-',dir=parent))
        metadata['artifact_dir']=str(folder) if temp_work_dir is not None else None
        snapshots={}
        for key,source,name,limit in [('helper',helper_path,'helper.exe',64*1024*1024),('dia_dll',dia_dll,'msdia140.dll',64*1024*1024),('pdb',pdb_path,'input.pdb',512*1024*1024)]:
            snapshots[key]=folder/name
            metadata[key+'_sha256']=create_verified_snapshot(source,snapshots[key],max_bytes=limit)
        if binary_path is not None:
            snapshots['binary']=folder/'input.exe'
            metadata['binary_sha256']=create_verified_snapshot(binary_path,snapshots['binary'],max_bytes=512*1024*1024)
            if metadata['binary_sha256'] in (metadata['helper_sha256'], metadata['dia_dll_sha256']):
                return failed('target_tool_alias')
        proc = run_bounded(
            [str(snapshots['helper']),str(snapshots['dia_dll']),str(snapshots['pdb']),str(max_symbols)],
            timeout=float(timeout),
            memory_limit_mb=memory_limit_mb,
            output_limit_bytes=_MAX_OUTPUT,require_process_tree=True,
        )
        metadata['worker_execution']={k:v for k,v in proc.items() if k not in ('stdout','stderr')}
        metadata['helper_stdout_sha256']=hashlib.sha256(str(proc.get('stdout') or '').encode('utf-8')).hexdigest()
        metadata['returncode']=proc.get('returncode')
        for key,path in snapshots.items():
            if not _regular(path) or _sha256(path)!=metadata[key+'_sha256']:return failed('private_snapshot_changed')
        if proc.get('timed_out'):return failed('helper_timeout')
        if proc.get('resource_exceeded'):return failed('helper_resource_exceeded')
        if proc.get('returncode')!=0:return failed('helper_failed')
        if proc.get('capture_complete') is not True:return failed('helper_capture_incomplete')
        if proc.get('process_tree_contained') is not True:return failed('helper_tree_uncontained')
        stdout=proc.get('stdout')
        if not isinstance(stdout,str) or len(stdout.encode('utf-8'))>_MAX_OUTPUT:return failed('helper_output_too_large')
        def unique(pairs):
            result={}
            for k,v in pairs:
                if k in result:raise ValueError('duplicate_json_key')
                result[k]=v
            return result
        raw=json.loads(stdout,object_pairs_hook=unique,parse_constant=lambda x:(_ for _ in ()).throw(ValueError('nonfinite_json')))
        if not isinstance(raw,dict) or raw.get('schema')!=SCHEMA or raw.get('status')!='complete':return failed('helper_report_invalid')
        if set(raw)-_RAW_FIELDS:return failed('helper_unrecognized_claim_or_field')
        capabilities=raw.get('capabilities')
        if (not isinstance(capabilities,list) or len(capabilities)>16 or any(not isinstance(c,str) or c not in {'source_file','is_static','function_types'} for c in capabilities)
            or len(set(capabilities))!=len(capabilities)):return failed('helper_capabilities_invalid')
        if (type(raw.get('enumeration_complete',True)) is not bool
            or 'function_types' in capabilities and 'enumeration_complete' not in raw):
            return failed('helper_enumeration_invalid')
        symbols=raw.get('symbols');count=raw.get('count')
        if not isinstance(symbols,list) or type(count) is not int or count!=len(symbols) or not 0<=count<=max_symbols or type(raw.get('truncated')) is not bool:
            return failed('helper_inventory_invalid')
        try:guid=str(uuid.UUID(raw.get('guid','').strip('{}'))).upper()
        except (ValueError,AttributeError,TypeError):return failed('helper_identity_invalid')
        if type(raw.get('age')) is not int or not 0<=raw['age']<2**32 or type(raw.get('machine')) is not int or not 0<=raw['machine']<2**32:return failed('helper_identity_invalid')
        identities=set()
        for symbol in symbols:
            if (not isinstance(symbol,dict) or not isinstance(symbol.get('name'),str) or not 0<len(symbol['name'])<=4096
                or type(symbol.get('rva')) is not int or not 0<=symbol['rva']<2**32
                or type(symbol.get('length')) is not int or not 0<=symbol['length']<2**64
                or type(symbol.get('sym_index')) is not int or not 0<symbol['sym_index']<2**32 or symbol['sym_index'] in identities
                or type(symbol.get('sym_tag')) is not int or symbol['sym_tag']!=5 or type(symbol.get('is_static')) is not bool
                or not isinstance(symbol.get('source_file'),str) or len(symbol['source_file'])>32768
                or set(symbol)-{'name','rva','length','sym_tag','sym_index','is_static','source_file','function_type'}):return failed('helper_symbols_invalid')
            identities.add(symbol['sym_index'])
        coverage=_type_inventory(raw,symbols,capabilities)
        binding=dict(status='not_requested',target_types_bound=False)
        if binary_path is not None:
            cv=parse_pe_codeview(snapshots['binary'].read_bytes())
            if (cv.get('status')!='complete' or cv.get('machine')!=raw['machine']
                or not any(r.get('guid','').strip('{}').upper()==guid and r.get('age')==raw['age'] for r in cv.get('records',[]))):
                return failed('pe_pdb_identity_mismatch')
            binding=dict(status='verified',target_identity_bound=True,target_types_bound=coverage['status']=='observed_complete',guid='{'+guid+'}',age=raw['age'],machine=raw['machine'],
                binary_sha256=metadata['binary_sha256'],pdb_sha256=metadata['pdb_sha256'])
        report={**raw,**metadata,'status':'partial' if raw['truncated'] or raw.get('enumeration_complete') is False or coverage['status']=='partial' else 'complete','binding':binding,
            'validated_payload_sha256':_payload_digest(raw),
            'type_coverage':coverage,'binary_equivalence_proved':False,'type_recovery_proved':False,'original_source_recovered':False,
            'pdb':str(pdb_path),'helper':str(helper_path),'dia_dll':str(dia_dll),'executed_target':False,
            'limitations':['debug identity and observed symbols do not prove original source or binary behavior']}
        report['validated_report_sha256']=_report_digest(report)
        return report
    except (OSError,ValueError,TypeError,UnicodeError,RecursionError) as exc:
        return failed('helper_execution_or_contract_invalid',type(exc).__name__+':'+str(exc)[:200])
    finally:
        if context is not None:context.cleanup()


def pdb_return_contract(report, *, target_sha256, function_rva):
    """Select a scalar debug return type from one freshly verified DIA report.

    Identity/type observations remain distinct from behavior certification.
    """
    if (not isinstance(report,dict) or report.get('validated_payload_sha256')!=_payload_digest(report)
        or report.get('validated_report_sha256')!=_report_digest(report)):
        raise ValueError('pdb_return_payload_changed')
    if (report.get('status')!='complete' or report.get('binary_sha256')!=target_sha256
        or report.get('binding',{}).get('target_types_bound') is not True
        or report.get('binding',{}).get('binary_sha256')!=target_sha256
        or type(function_rva) is not int or not 0<=function_rva<2**32):raise ValueError('pdb_return_binding_unavailable')
    coverage=_type_inventory(report,report['symbols'],report['capabilities'])
    if coverage['status']!='observed_complete':raise ValueError('pdb_return_types_incomplete')
    matches=[s for s in report['symbols'] if s['rva']==function_rva]
    if len(matches)!=1:raise ValueError('pdb_return_rva_absent_or_ambiguous')
    symbol=matches[0];types={t['id']:t for t in report['types']};signature=types[symbol['function_type']]
    identity=signature['target'];visited=set()
    while identity in types and types[identity]['tag'] in {12,17}:
        if identity in visited:raise ValueError('pdb_return_type_cycle')
        visited.add(identity);identity=types[identity]['target']
    node=types.get(identity)
    if (node is None or node['tag']!=16 or node['base_type'] not in {6,7,13,14}
        or node['length'] not in {1,2,4,8}):raise ValueError('pdb_return_type_not_supported_integer')
    return dict(schema='pdb-scalar-return.v1',target_sha256=target_sha256,function_rva=function_rva,
        function_sym_index=symbol['sym_index'],signature_type_id=signature['id'],type_id=identity,
        return_bits=node['length']*8,signed=node['base_type'] in {6,13},calling_convention=signature['calling_convention'],
        pdb_sha256=report['pdb_sha256'],helper_sha256=report['helper_sha256'],dia_dll_sha256=report['dia_dll_sha256'],
        payload_sha256=report['validated_payload_sha256'],guid=report['binding']['guid'],age=report['binding']['age'],
        type_recovery_proved=False,binary_equivalence_proved=False,
        limitations=['observed linked PDB scalar type, not behavior proof or complete ABI recovery'])


def write_pdb_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
