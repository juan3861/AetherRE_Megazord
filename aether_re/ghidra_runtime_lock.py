"""Complete bounded local Ghidra/JDK byte pins, without execution or attestation.

Checks observe stable files and inventories at discrete times. They cannot make
a writable installation immutable or authenticate its upstream acquisition.
"""
from __future__ import annotations

import hashlib,json,os,re,stat,unicodedata
from pathlib import Path
from .evidence import _has_link_or_reparse_component

MAX_FILES=20000
MAX_ENTRIES=40000
MAX_FILE_BYTES=512*1024**2
MAX_TOTAL_BYTES=4*1024**3
MAX_LOCK_BYTES=4*1024**2
SCHEMA='ghidra-runtime-lock.v1'
_ESSENTIAL={'ghidra':{'Ghidra/Framework/Utility/lib/Utility.jar','Ghidra/application.properties','support/analyzeHeadless.bat'},
            'jdk':{'bin/java.exe','release'}}


def _local_path(value):
    if not isinstance(value,(str,Path)) or not 1<=len(str(value))<=32768 or '\0' in str(value):
        raise ValueError('runtime_lock_path_invalid')
    path=Path(value).absolute()
    if str(path).startswith(('\\\\','//')):raise ValueError('runtime_lock_remote_path_refused')
    return path


def _name(value):
    if (type(value) is not str or not 1<=len(value)<=4096 or value!=unicodedata.normalize('NFC',value)
            or any(ord(c)<32 for c in value) or any(c in value for c in '\\:<>"|?*')):
        raise ValueError('runtime_lock_name_invalid')
    for part in value.split('/'):
        if (not part or part in ('.','..') or part[-1] in ' .'
                or re.fullmatch(r'(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])',part.split('.')[0],re.I)):
            raise ValueError('runtime_lock_name_invalid')
    return value


def _fingerprint(info):
    # Windows path stat synthesizes executable permission bits from suffixes;
    # handle fstat does not, and its legacy ctime can use another timestamp.
    return (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,
            stat.S_IFMT(info.st_mode),getattr(info,'st_file_attributes',0),info.st_nlink)


def _ordinary(info,directory=False):
    if (getattr(info,'st_file_attributes',0)&0x400 or stat.S_ISLNK(info.st_mode)
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or (not directory and info.st_nlink!=1)):
        raise ValueError('runtime_lock_entry_not_ordinary')


def _roots(ghidra_home,jdk_home):
    result={}
    for key,value in [('ghidra',ghidra_home),('jdk',jdk_home)]:
        path=_local_path(value)
        if _has_link_or_reparse_component(path):raise ValueError('runtime_lock_root_link')
        _ordinary(path.lstat(),True);result[key]=path.resolve(strict=True)
    g,j=result.values()
    if g==j or g in j.parents or j in g.parents:raise ValueError('runtime_lock_roots_overlap')
    return result


def _census(roots):
    result={};files=0;total=0;entries=0
    for key,root in roots.items():
        rows={'':('dir',_fingerprint(root.lstat()))};folded=set()
        for parent,dirs,names in os.walk(root,followlinks=False,onerror=lambda error: (_ for _ in ()).throw(error)):
            for name,is_dir in [(n,True) for n in dirs]+[(n,False) for n in names]:
                path=Path(parent)/name;relative=_name(path.relative_to(root).as_posix());fold=relative.casefold()
                if fold in folded:raise ValueError('runtime_lock_case_collision')
                folded.add(fold);info=path.lstat();_ordinary(info,is_dir)
                entries+=1
                if entries>MAX_ENTRIES:raise ValueError('runtime_lock_entry_budget')
                if not is_dir:
                    files+=1;total+=info.st_size
                    if info.st_size>MAX_FILE_BYTES or files>MAX_FILES or total>MAX_TOTAL_BYTES:
                        raise ValueError('runtime_lock_byte_or_file_budget')
                rows[relative]=('dir' if is_dir else 'file',_fingerprint(info))
        result[key]=rows
    return result


def _scan(roots):
    before=_census(roots);bundles={}
    for key,root in roots.items():
        files={}
        for name,(kind,expected) in sorted(before[key].items()):
            if kind=='dir':continue
            path=root/name;digest=hashlib.sha256();count=0
            with path.open('rb') as h:
                opened=os.fstat(h.fileno());_ordinary(opened)
                if _fingerprint(opened)!=expected:raise ValueError('runtime_lock_file_changed')
                while chunk:=h.read(min(1024**2,MAX_FILE_BYTES-count+1)):
                    count+=len(chunk)
                    if count>MAX_FILE_BYTES:raise ValueError('runtime_lock_file_budget')
                    digest.update(chunk)
                after=os.fstat(h.fileno())
            if count!=opened.st_size or _fingerprint(after)!=expected or _fingerprint(path.lstat())!=expected:
                raise ValueError('runtime_lock_file_changed')
            files[name]={'bytes':count,'sha256':digest.hexdigest()}
        bundles[key]={'files':files}
    if _census(roots)!=before:raise ValueError('runtime_lock_tree_changed')
    return {'schema':SCHEMA,'bundles':bundles}


def _validate(lock):
    if type(lock) is not dict or set(lock)!={'schema','bundles'} or lock['schema']!=SCHEMA:
        raise ValueError('runtime_lock_schema_invalid')
    if type(lock['bundles']) is not dict or set(lock['bundles'])!=set(_ESSENTIAL):
        raise ValueError('runtime_lock_bundles_invalid')
    count=0;total=0;result={}
    for key in sorted(_ESSENTIAL):
        bundle=lock['bundles'][key]
        if type(bundle) is not dict or set(bundle)!={'files'} or type(bundle['files']) is not dict:
            raise ValueError('runtime_lock_bundle_invalid')
        if not _ESSENTIAL[key]<=set(bundle['files']):raise ValueError('runtime_lock_essential_missing')
        files={};folded=set()
        for name,item in bundle['files'].items():
            _name(name)
            if name.casefold() in folded:raise ValueError('runtime_lock_case_collision')
            folded.add(name.casefold())
            if (type(item) is not dict or set(item)!={'bytes','sha256'} or type(item['bytes']) is not int
                    or not 0<=item['bytes']<=MAX_FILE_BYTES or type(item['sha256']) is not str
                    or re.fullmatch('[0-9a-f]{64}',item['sha256']) is None):
                raise ValueError('runtime_lock_file_metadata_invalid')
            count+=1;total+=item['bytes']
            if count>MAX_FILES or total>MAX_TOTAL_BYTES:raise ValueError('runtime_lock_byte_or_file_budget')
            files[name]=dict(item)
        result[key]={'files':dict(sorted(files.items()))}
    return {'schema':SCHEMA,'bundles':result}


def runtime_lock_bytes(lock):
    raw=(json.dumps(_validate(lock),sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode('utf-8')
    if len(raw)>MAX_LOCK_BYTES:raise ValueError('runtime_lock_manifest_budget')
    return raw


def build_ghidra_runtime_lock(ghidra_home,jdk_home):
    """Read two complete ordinary local trees; create no files and execute nothing."""
    roots=_roots(ghidra_home,jdk_home);first=_scan(roots);_validate(first)
    if _scan(roots)!=first:raise ValueError('runtime_lock_passes_disagree')
    runtime_lock_bytes(first)
    return first


def verify_ghidra_runtime_lock(lock,ghidra_home,jdk_home):
    expected=_validate(lock);raw=runtime_lock_bytes(expected);roots=_roots(ghidra_home,jdk_home)
    observed=_scan(roots);errors=[]
    for key in sorted(_ESSENTIAL):
        a=expected['bundles'][key]['files'];b=observed['bundles'][key]['files']
        if set(a)-set(b):errors.append(key+':files_missing')
        if set(b)-set(a):errors.append(key+':files_added')
        if any(a[name]!=b[name] for name in set(a)&set(b)):errors.append(key+':file_bytes_differ')
    return dict(schema='ghidra-runtime-verification.v1',verified=not errors,errors=errors,
        manifest_sha256=hashlib.sha256(raw).hexdigest(),roots={k:str(v) for k,v in roots.items()},
        file_count=sum(len(x['files']) for x in observed['bundles'].values()),
        total_bytes=sum(i['bytes'] for b in observed['bundles'].values() for i in b['files'].values()),
        upstream_authenticity_proved=False,continuous_execution_integrity_proved=False,
        scope='complete stable local files at this check; not acquisition authenticity or immutable execution')


def read_ghidra_runtime_lock(path):
    path=_local_path(path)
    if _has_link_or_reparse_component(path):raise ValueError('runtime_lock_input_link')
    before=path.lstat();_ordinary(before)
    if not 0<before.st_size<=MAX_LOCK_BYTES:raise ValueError('runtime_lock_manifest_budget')
    with path.open('rb') as h:
        opened=os.fstat(h.fileno());_ordinary(opened);raw=h.read(MAX_LOCK_BYTES+1);after=os.fstat(h.fileno())
    if len(raw)!=before.st_size or not _fingerprint(before)==_fingerprint(opened)==_fingerprint(after)==_fingerprint(path.lstat()):
        raise ValueError('runtime_lock_input_changed')
    def unique(pairs):
        out={}
        for key,value in pairs:
            if key in out:raise ValueError('runtime_lock_duplicate_json_key')
            out[key]=value
        return out
    lock=json.loads(raw.decode('utf-8'),object_pairs_hook=unique)
    _validate(lock);runtime_lock_bytes(lock)
    return dict(path=str(path),raw_sha256=hashlib.sha256(raw).hexdigest(),manifest=lock)
