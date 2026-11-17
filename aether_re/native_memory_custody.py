"""Separate, replayable memory derivations using existing evidence-kernel primitives."""
from __future__ import annotations
import hashlib
import json
import os
import shutil
import tempfile
import re
from dataclasses import asdict,dataclass
from pathlib import Path

from .custody import create_custody_receipt,verify_custody_receipt
from .evidence import read_bounded_bytes,_has_link_or_reparse_component
from .evidence_journal import EvidenceJournal
from .evidence_store import EvidenceStore
from .intake import IntakeRequest,prepare_case,_new_atomic_json
from .kernel_contracts import ArtifactRef,AuthorizationPolicy,DerivationRecord,EpistemicState,IntakeLimits,canonical_json,sha256_canonical
from .native_memory import build_pe_memory,build_elf_memory,MAX_FILE_BYTES

MAX_REPORT_BYTES=16*1024*1024
_ADMISSION_TOKEN=object()

@dataclass(frozen=True)
class AdmittedMemoryContext:
    """Immutable metadata captured after full bundle verification, not live file health."""
    directory: str
    _reference: bytes
    _summary: bytes
    receipt_sha256: str
    _admission: object

    def __post_init__(self):
        if self._admission is not _ADMISSION_TOKEN:raise ValueError('memory_context_not_admitted')

    @property
    def target_sha256(self):return json.loads(self._summary)['target_sha256']

    def bind(self,*,target_sha256,space_id,image_base,bits,endian):
        expected=_context_values(target_sha256,space_id,image_base,bits,endian)
        summary=json.loads(self._summary)
        if any(summary.get(key)!=value for key,value in expected.items()):raise ValueError('memory_context_mismatch')
        return dict(status='bound',report=json.loads(self._reference),directory=self.directory,context=summary,
            receipt_sha256=self.receipt_sha256,admission_scope='verified_bundle_snapshot',
            contiguous_runtime_compatible=summary['contiguous_runtime_compatible'],process_snapshot_proved=False,binary_equivalence_proved=False)

def admit_memory_context(directory):
    directory=_safe(directory);_preflight_kernel(directory)
    receipt=read_bounded_bytes(directory/'custody-receipt.json',max_bytes=1024*1024)
    manifest=read_bounded_bytes(directory/'manifest.json',max_bytes=MAX_REPORT_BYTES)
    verification=verify_memory_derivation(directory)
    if verification['status']!='pass':raise ValueError('memory_context_derivation_invalid')
    ref=ArtifactRef.from_dict(verification['report']);_,raw=_input(EvidenceStore(directory),ref);report=json.loads(raw)
    regions=report.get('regions',[report])
    summary={key:report[key] for key in ('schema','target_sha256','space_id','base','machine','bits','endian','image_base_kind')}
    summary.update(region_count=len(regions),materialized_bytes=sum(r['buffers']['bytes']['size'] for r in regions),
        unknown_range_count=len(report['unknown_ranges']),contiguous_runtime_compatible=report.get('contiguous_runtime_compatible',True))
    if 'analysis_addressing' in report:summary['analysis_addressing']=report['analysis_addressing']
    if (receipt!=read_bounded_bytes(directory/'custody-receipt.json',max_bytes=1024*1024)
        or manifest!=read_bounded_bytes(directory/'manifest.json',max_bytes=MAX_REPORT_BYTES)
        or json.loads(manifest)['report']!=ref.to_dict()):raise ValueError('memory_context_changed_during_admission')
    return AdmittedMemoryContext(str(directory),canonical_json(ref.to_dict()),canonical_json(summary),hashlib.sha256(receipt).hexdigest(),_ADMISSION_TOKEN)

def _context_values(target_sha256,space_id,image_base,bits,endian):
    if (not isinstance(target_sha256,str) or not re.fullmatch('[0-9a-f]{64}',target_sha256)
        or type(space_id) is not int or not 0<=space_id<=0xffffffff
        or type(image_base) is not int or not 0<=image_base<1<<64
        or type(bits) is not int or bits not in (32,64) or endian not in ('little','big')):
        raise ValueError('memory_context_invalid')
    return dict(target_sha256=target_sha256,space_id=space_id,base=image_base,bits=bits,endian=endian)

def validate_memory_reference(reference,model,selector):
    if reference is None:return
    if (model not in ('bounded-bytes.v1','bounded-bytes.v2') or not isinstance(selector,str) or not 1<=len(selector)<=4096 or not selector.strip()
        or not isinstance(reference,(str,Path)) or not 1<=len(str(reference))<=32768 or not str(reference).strip() or '\0' in str(reference)):
        raise ValueError('memory_derivation_requires_path_model_and_selection')

def admit_memory_for_target(directory,target):
    from .evidence import sha256_file_bounded
    context=admit_memory_context(directory)
    if sha256_file_bounded(Path(target),MAX_FILE_BYTES)!=context.target_sha256:raise ValueError('memory_derivation_target_mismatch')
    return context

def _json(path,limit=MAX_REPORT_BYTES):
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:raise ValueError('memory_json_duplicate')
            result[key]=value
        return result
    value=json.loads(read_bounded_bytes(path,max_bytes=limit),object_pairs_hook=unique,
        parse_constant=lambda v:(_ for _ in ()).throw(ValueError('memory_json_constant')))
    if type(value) is not dict:raise ValueError('memory_json_object')
    return value

def _safe(path):
    path=Path(path)
    if '..' in path.parts or _has_link_or_reparse_component(path):raise ValueError('memory_path_unsafe')
    return path.absolute()

def _input(store,ref):
    if ref.size>MAX_FILE_BYTES:raise ValueError('memory_input_budget')
    path=_safe(store.root/ref.object_path)
    if path.stat().st_nlink!=1:raise ValueError('memory_object_hardlinked')
    try:store.verify(ref)
    except Exception as exc:raise ValueError('memory_input_integrity') from exc
    data=read_bounded_bytes(path,max_bytes=MAX_FILE_BYTES)
    if hashlib.sha256(data).hexdigest()!=ref.sha256:raise ValueError('memory_input_changed')
    return path,data

def _preflight_kernel(directory):
    limits={'manifest.json':MAX_REPORT_BYTES,'journal.jsonl':2*1024*1024,'journal.head.json':65536,'custody-receipt.json':1024*1024}
    for name,limit in limits.items():
        path=_safe(directory/name)
        if not path.is_file() or path.stat().st_nlink!=1 or path.stat().st_size>limit:
            raise ValueError('memory_kernel_file_budget_or_type')

def _options(profile,space_id,sparse):
    if profile not in ('pe','elf') or type(space_id) is not int or not 0<=space_id<=0xffffffff or type(sparse) is not bool or profile=='pe' and sparse:
        raise ValueError('memory_derivation_options')

def _build(data,profile,space_id,sparse,analysis_base=None):
    digest=hashlib.sha256(data).hexdigest()
    return (build_pe_memory(data,target_sha256=digest,space_id=space_id) if profile=='pe'
        else build_elf_memory(data,target_sha256=digest,space_id=space_id,sparse=sparse,analysis_base=analysis_base))

def _pack(memory,put):
    def one(region,index):
        result={k:v for k,v in region.items() if k not in ('bytes','permissions','initialized')}
        result['buffers']={key:put(region[key],f'region{index}:{key}').to_dict() for key in ('bytes','permissions','initialized')}
        return result
    if 'regions' in memory:
        return {**{k:v for k,v in memory.items() if k!='regions'},'regions':[one(r,i) for i,r in enumerate(memory['regions'])]}
    return one(memory,0)

def publish_memory_derivation(case_dir,destination,*,profile,space_id,sparse=False,analysis_base=None):
    _options(profile,space_id,sparse)
    if analysis_base is not None and (profile!='elf' or type(analysis_base) is not int or not 0<=analysis_base<1<<64):
        raise ValueError('memory_analysis_base_option')
    parent=_safe(case_dir);dest=_safe(destination)
    if parent==dest or parent in dest.parents or dest in parent.parents:raise ValueError('memory_destination_overlap')
    if dest.exists():raise FileExistsError('memory_destination_exists')
    if not dest.parent.is_dir() or shutil.disk_usage(dest.parent).free<128*1024*1024:raise ValueError('memory_disk_reserve')
    _preflight_kernel(parent)
    parent_manifest=parent/'manifest.json';parent_journal=parent/'journal.jsonl';parent_receipt=parent/'custody-receipt.json'
    custody=verify_custody_receipt(parent_receipt,expected_artifacts={'manifest':parent_manifest,'journal':parent_journal})
    if custody['status']!='pass' or custody['artifact_count']!=2:raise ValueError('memory_parent_custody')
    if EvidenceJournal(parent).verify().status!='pass':raise ValueError('memory_parent_journal')
    manifest=_json(parent_manifest)
    if manifest.get('schema')!='universal-intake-manifest.v1':raise ValueError('memory_parent_schema')
    authorization=AuthorizationPolicy.from_dict(manifest['authorization']);auth_hash=sha256_canonical(authorization.to_dict())
    source=ArtifactRef.from_dict(manifest['root_artifact'])
    if source.authorization_sha256!=sha256_canonical(asdict(authorization)) or manifest['authorization_sha256']!=auth_hash or not authorization.allows('static-analysis'):
        raise ValueError('memory_parent_authorization')
    source_path,data=_input(EvidenceStore(parent),source)
    memory=_build(data,profile,space_id,sparse,analysis_base)
    parent_hash=hashlib.sha256(read_bounded_bytes(parent_manifest,max_bytes=MAX_REPORT_BYTES)).hexdigest()
    dest.mkdir(exist_ok=False);journal=EvidenceJournal.open(dest);store=EvidenceStore(dest)
    try:
        journal.append('derivation.opened',{'parent_manifest_sha256':parent_hash,'input_sha256':source.sha256})
        copied=store.publish_file(source_path,media_type=source.media_type,origin='memory-input',authorization=authorization,max_bytes=MAX_FILE_BYTES)
        if copied.sha256!=source.sha256:raise ValueError('memory_source_changed')
        journal.append('artifact.published',{'artifact':copied.to_dict()})
        refs=[]
        with tempfile.TemporaryDirectory(prefix='.memory-stage-',dir=dest) as staging:
            def put(blob,label):
                if len(blob)>MAX_REPORT_BYTES:raise ValueError('memory_product_budget')
                path=Path(staging)/str(len(refs))
                with path.open('xb') as handle:handle.write(blob);handle.flush();os.fsync(handle.fileno())
                ref=store.publish_file(path,media_type='application/octet-stream',origin='memory:'+label,authorization=authorization,max_bytes=MAX_REPORT_BYTES)
                journal.append('artifact.published',{'artifact':ref.to_dict()});refs.append(ref);return ref
            report=_pack(memory,put);encoded=canonical_json(report)
            product=put(encoded,'report')
        record=DerivationRecord('derivation-record.v1','memory-'+product.sha256,product.artifact_id,EpistemicState.HYPOTHESIS,None,
            tuple(sorted({copied.artifact_id,*[r.artifact_id for r in refs[:-1]]})),product=product,
            producer={'name':'native-memory','version':'12'},method='static-file-memory.v1',
            limitations=('static addresses and format assumptions; not a process snapshot','local hash integrity is not WORM or external certification'))
        if verify_custody_receipt(parent_receipt,expected_artifacts={'manifest':parent_manifest,'journal':parent_journal})['status']!='pass':raise ValueError('memory_parent_changed')
        if hashlib.sha256(read_bounded_bytes(parent_manifest,max_bytes=MAX_REPORT_BYTES)).hexdigest()!=parent_hash:raise ValueError('memory_parent_changed')
        result=dict(schema='native-memory-derivation.v1',authorization=authorization.to_dict(),parent_manifest_sha256=parent_hash,
            input=copied.to_dict(),profile=profile,space_id=space_id,sparse=sparse,report=product.to_dict(),derivation=record.to_dict())
        if analysis_base is not None:result['analysis_base']=analysis_base
        _new_atomic_json(result,dest/'manifest.json')
        journal.append('derivation.completed',{'manifest_sha256':hashlib.sha256((dest/'manifest.json').read_bytes()).hexdigest()})
        receipt=create_custody_receipt({'manifest':dest/'manifest.json','journal':journal.path},dest/'custody-receipt.json')
        if receipt.get('status')!='created':raise ValueError('memory_custody_failed')
        if verify_memory_derivation(dest)['status']!='pass':raise ValueError('memory_postpublication_verification')
        return dict(status='complete',report=product.to_dict(),manifest_path=str(dest/'manifest.json'),process_snapshot_proved=False)
    except BaseException:
        try:journal.append('derivation.failed',{'code':'memory_derivation_incomplete'})
        except Exception:pass
        raise

def verify_memory_derivation(directory):
    try:
        directory=_safe(directory)
        if not directory.is_dir():raise ValueError('memory_derivation_missing')
        _preflight_kernel(directory)
        paths={'manifest':directory/'manifest.json','journal':directory/'journal.jsonl'}
        custody=verify_custody_receipt(directory/'custody-receipt.json',expected_artifacts=paths)
        if custody['status']!='pass' or custody['artifact_count']!=2:raise ValueError('memory_derivation_custody')
        if EvidenceJournal(directory).verify().status!='pass':raise ValueError('memory_derivation_journal')
        manifest=_json(paths['manifest'])
        required={'schema','authorization','parent_manifest_sha256','input','profile','space_id','sparse','report','derivation'}
        if set(manifest) not in (required,required|{'analysis_base'}) or manifest['schema']!='native-memory-derivation.v1':raise ValueError('memory_derivation_schema')
        if 'analysis_base' in manifest and (manifest['profile']!='elf' or type(manifest['analysis_base']) is not int or not 0<=manifest['analysis_base']<1<<64):raise ValueError('memory_analysis_base_option')
        if not isinstance(manifest['parent_manifest_sha256'],str) or not re.fullmatch('[0-9a-f]{64}',manifest['parent_manifest_sha256']):raise ValueError('memory_parent_hash')
        _options(manifest['profile'],manifest['space_id'],manifest['sparse'])
        auth=AuthorizationPolicy.from_dict(manifest['authorization']);auth_hash=sha256_canonical(asdict(auth))
        if not auth.allows('static-analysis'):raise ValueError('memory_derivation_authorization')
        store=EvidenceStore(directory);input_ref=ArtifactRef.from_dict(manifest['input']);_,data=_input(store,input_ref)
        report_ref=ArtifactRef.from_dict(manifest['report']);_,raw=_input(store,report_ref)
        report=_json(store.resolve(report_ref));expected=_build(data,manifest['profile'],manifest['space_id'],manifest['sparse'],manifest.get('analysis_base'))
        refs=[input_ref,report_ref];parts=[]
        regions=report.get('regions',[report])
        if type(regions) is not list or not 1<=len(regions)<=128:raise ValueError('memory_regions_shape')
        for region in regions:
            if type(region) is not dict or type(region.get('buffers')) is not dict or set(region['buffers'])!={'bytes','permissions','initialized'}:raise ValueError('memory_buffers_shape')
            for key in ('bytes','permissions','initialized'):parts.append((ArtifactRef.from_dict(region['buffers'][key]),key))
        counter=iter(parts)
        def check(blob,label):
            ref,key=next(counter);_,stored=_input(store,ref)
            if stored!=blob or ref.origin!='memory:'+label:raise ValueError('memory_product_semantic_mismatch')
            refs.append(ref);return ref
        if canonical_json(_pack(expected,check))!=canonical_json(report):raise ValueError('memory_report_semantic_mismatch')
        if next(counter,None) is not None:raise ValueError('memory_extra_buffers')
        if any(ref.authorization_sha256!=auth_hash for ref in refs):raise ValueError('memory_product_authorization')
        record=DerivationRecord.from_dict(manifest['derivation'])
        if record.product!=report_ref or record.epistemic_state!=EpistemicState.HYPOTHESIS or set(record.parents)!={ref.artifact_id for ref in refs if ref!=report_ref}:
            raise ValueError('memory_derivation_binding')
        if record.derivation_id!='memory-'+report_ref.sha256 or record.method!='static-file-memory.v1' or dict(record.producer)!={'name':'native-memory','version':'12'}:
            raise ValueError('memory_derivation_method')
        events=[json.loads(line) for line in read_bounded_bytes(paths['journal'],max_bytes=2*1024*1024).splitlines()]
        if not events or events[-1]['kind']!='derivation.completed' or events[-1]['payload']!={'manifest_sha256':hashlib.sha256(paths['manifest'].read_bytes()).hexdigest()}:
            raise ValueError('memory_completion_binding')
        if events[0]['kind']!='derivation.opened' or events[0]['payload']!={'parent_manifest_sha256':manifest['parent_manifest_sha256'],'input_sha256':input_ref.sha256}:
            raise ValueError('memory_open_binding')
        middle=events[1:-1]
        if len(middle)!=len(refs) or any(e['kind']!='artifact.published' or set(e['payload'])!={'artifact'} for e in middle):raise ValueError('memory_publication_events')
        if sorted(canonical_json(e['payload']['artifact']) for e in middle)!=sorted(canonical_json(ref.to_dict()) for ref in refs):raise ValueError('memory_publication_binding')
        return dict(status='pass',report=report_ref.to_dict(),external_anchor=False,process_snapshot_proved=False)
    except Exception as exc:return dict(status='fail',error=type(exc).__name__+':'+str(exc)[:200])

def replay_memory_derivation(directory,destination):
    if verify_memory_derivation(directory)['status']!='pass':raise ValueError('memory_replay_source_invalid')
    source=_safe(directory);dest=_safe(destination)
    if source==dest or source in dest.parents or dest in source.parents:raise ValueError('memory_replay_overlap')
    manifest=_json(source/'manifest.json');ref=ArtifactRef.from_dict(manifest['input'])
    path,_=_input(EvidenceStore(source),ref)
    dest.mkdir(exist_ok=False)
    admitted=prepare_case(IntakeRequest(path,dest/'input',AuthorizationPolicy.from_dict(manifest['authorization']),IntakeLimits(),False))
    result=publish_memory_derivation(admitted.manifest_path.parent,dest/'map',profile=manifest['profile'],space_id=manifest['space_id'],sparse=manifest['sparse'],analysis_base=manifest.get('analysis_base'))
    if result['report']['sha256']!=manifest['report']['sha256'] or verify_memory_derivation(dest/'map')['status']!='pass':raise ValueError('memory_replay_product_mismatch')
    return result

def bind_memory_derivation(directory,*,target_sha256,space_id,image_base,bits,endian):
    """Bind a verified static product to explicit caller context, without execution."""
    expected=_context_values(target_sha256,space_id,image_base,bits,endian)
    directory=_safe(directory);verification=verify_memory_derivation(directory)
    if verification['status']!='pass':raise ValueError('memory_context_derivation_invalid')
    ref=ArtifactRef.from_dict(verification['report']);_,raw=_input(EvidenceStore(directory),ref)
    report=json.loads(raw)
    if any(report.get(key)!=value for key,value in expected.items()):raise ValueError('memory_context_mismatch')
    return dict(status='bound',report=ref.to_dict(),memory=report,
        contiguous_runtime_compatible=report.get('contiguous_runtime_compatible',True),
        process_snapshot_proved=False,binary_equivalence_proved=False)
