"""Bounded byte intake and local snapshots for native address observation."""
from __future__ import annotations

from copy import deepcopy
import hashlib,os,stat,tempfile
from pathlib import Path
from .evidence import create_verified_snapshot,_has_link_or_reparse_component

LANGUAGE_NAMES=('ia.sinc','x86.slaspec','x86-64.slaspec')


def _path(value):
    if (not isinstance(value,(str,Path)) or not 1<=len(str(value))<=32768
            or not str(value).strip() or '\0' in str(value)):
        raise ValueError('native_frame_input_path_invalid')
    return Path(value).absolute()


def validate_native_frame_request(selector,object_bytes,language_dir,**options):
    if selector is None and object_bytes is None and language_dir is None:return
    if (type(selector) is not str or not selector.strip() or len(selector)>4096 or '\0' in selector
            or type(object_bytes) is not int or not 1<=object_bytes<=4096):
        raise ValueError('native_frame_request_requires_selector_extent_language')
    _path(language_dir)
    for name in ('derive_frame_function','frame_fact','reconstruct_function','memory_model','memory_derivation','call_model','debug_pdb','dia_helper','dia_dll'):
        if options.get(name) is not None:raise ValueError('native_frame_request_option_conflict:'+name)
    if options.get('out') is not None and _path(options['out']).suffix.lower()=='.c':
        raise ValueError('native_frame_request_requires_json_output')


def _ordinary(info):return stat.S_ISREG(info.st_mode) and not getattr(info,'st_file_attributes',0)&0x400


def _read(path,max_bytes):
    path=_path(path);before=path.lstat()
    if not _ordinary(before) or not 0<before.st_size<=max_bytes:raise ValueError('native_frame_input_file_or_budget')
    with path.open('rb') as h:
        opened=os.fstat(h.fileno());raw=h.read(max_bytes+1);after=os.fstat(h.fileno())
    final=path.lstat();key=lambda info:(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns)
    if (len(raw)>max_bytes or len(raw)!=after.st_size or not all(_ordinary(i) for i in (opened,after,final))
            or not key(before)==key(opened)==key(after)==key(final)):
        raise ValueError('native_frame_input_changed_or_budget')
    return raw,dict(path=str(path),sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw))


def read_native_frame_inputs(target,language_dir):
    # Native decoder dependencies stay lazy for all disabled/default routes.
    from .native_frame_address import MAX_TARGET_BYTES,MAX_LANGUAGE_BYTES,validate_language_sources
    directory=_path(language_dir);language={};sources={}
    for name in LANGUAGE_NAMES:language[name],sources[name]=_read(directory/name,MAX_LANGUAGE_BYTES)
    validate_language_sources(language)
    raw,target_receipt=_read(target,MAX_TARGET_BYTES)
    receipt=dict(schema='native-frame-inputs.v1',target=target_receipt,language_sources=sources,
        target_executed=False,native_frame_fact_verified=False,language_toolchain_authenticity_proved=False,
        custody_scope='observed stable local bytes; not external custody')
    return dict(target_path=target_receipt['path'],target_bytes=raw,language_sources=language,receipt=receipt)


def _checked_packet(packet):
    from .native_frame_address import MAX_TARGET_BYTES,validate_language_sources
    if type(packet) is not dict:raise ValueError('native_frame_input_packet_invalid')
    try:
        raw=packet['target_bytes'];language=packet['language_sources'];receipt=deepcopy(packet['receipt'])
        if type(raw) is not bytes or not 0<len(raw)<=MAX_TARGET_BYTES:raise ValueError('native_frame_input_target_budget')
        validate_language_sources(language)
        if (type(receipt) is not dict or receipt.get('schema')!='native-frame-inputs.v1'
                or any(receipt.get(key) is not False for key in ('target_executed','native_frame_fact_verified','language_toolchain_authenticity_proved'))):
            raise ValueError('native_frame_input_receipt_invalid')
        for content,item in [(raw,receipt['target']),*((language[name],receipt['language_sources'][name]) for name in LANGUAGE_NAMES)]:
            _path(item['path'])
            if type(item['bytes']) is not int or item['bytes']!=len(content) or item['sha256']!=hashlib.sha256(content).hexdigest():
                raise ValueError('native_frame_input_packet_digest_mismatch')
        _path(packet['target_path'])
    except (KeyError,TypeError,AttributeError) as error:raise ValueError('native_frame_input_packet_invalid') from error
    return raw,language,receipt


def snapshot_native_frame_inputs(packet,destination,*,expected_target_sha256=None):
    from .native_frame_address import MAX_TARGET_BYTES,MAX_LANGUAGE_BYTES
    raw,language,receipt=_checked_packet(packet)
    if expected_target_sha256 is not None and receipt['target']['sha256']!=expected_target_sha256:
        raise ValueError('native_frame_input_target_mismatch')
    destination=_path(destination)
    if destination.exists() or destination.is_symlink() or _has_link_or_reparse_component(destination.parent):
        raise ValueError('native_frame_input_snapshot_create_only_or_parent_unsafe')
    destination.mkdir(parents=True,exist_ok=False)
    target=destination/'target.bin'
    create_verified_snapshot(_path(packet['target_path']),target,expected_sha256=receipt['target']['sha256'],max_bytes=MAX_TARGET_BYTES)
    raw_after,target_after=_read(target,MAX_TARGET_BYTES)
    if raw_after!=raw:raise ValueError('native_frame_input_snapshot_changed')
    receipt['target']['snapshot_path']=str(target)
    captured={}
    for name in LANGUAGE_NAMES:
        item=receipt['language_sources'][name];output=destination/name
        create_verified_snapshot(_path(item.get('snapshot_path',item['path'])),output,expected_sha256=item['sha256'],max_bytes=MAX_LANGUAGE_BYTES)
        captured[name],observed=_read(output,MAX_LANGUAGE_BYTES)
        if captured[name]!=language[name]:raise ValueError('native_frame_input_snapshot_changed')
        item['snapshot_path']=str(output)
    receipt['custody_scope']='local verified byte snapshots; not external custody'
    return dict(target_path=str(target),target_bytes=raw_after,language_sources=captured,receipt=receipt)


def native_input_destination(output=None):
    """Choose a new input bundle next to explicit JSON output or in private temp."""
    if output is not None:
        output=_path(output)
        if output.exists() or output.is_symlink():raise FileExistsError('native_frame_output_already_exists')
        return output.with_name(output.name+'.native-inputs')
    return Path(tempfile.mkdtemp(prefix='aether_native_frame_'))/'inputs'
