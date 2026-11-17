"""Build the explicitly supplied DIA helper with observed, bounded tool inputs.

This is a local build receipt, not a hermetic toolchain or release certificate.
No analyzed PE/PDB is executed by this module.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path

from aether_re.evidence import create_verified_snapshot, _has_link_or_reparse_component
from aether_re.process import run_bounded


def _hash(path):
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):digest.update(chunk)
    return digest.hexdigest()


def _regular(path):
    return path.is_file() and not _has_link_or_reparse_component(path) and path.stat().st_nlink==1


def _path(value):
    if not isinstance(value,(str,Path)) or not str(value).strip() or len(str(value))>32768:
        raise ValueError('build_path_invalid')
    # Batch parsing expands percent variables even inside double quotes. The
    # other rejected characters can terminate or create a command line.
    if any(c in str(value) for c in ('\0','\r','\n','"','%','!','^')):
        raise ValueError('build_path_invalid')
    return Path(value).absolute()


def build_dia_helper(*,vs_root,dia_sdk_root,source,out,work_dir=None,timeout=120,memory_limit_mb=2048):
    report=dict(schema='dia-helper-build.v1',status='unavailable',code='build_not_started',
        target_executed=False,hermetic_build_proved=False,certified=False,
        limitations=['explicit trusted compiler/VS scripts and owned helper source are executed',
            'key tool/SDK inputs observed; transitive Windows SDK/runtime are not fully snapshotted',
            'local build receipt is not release approval, WORM or binary equivalence'])
    def failed(code,detail=''):
        report.update(status='unavailable',code=code)
        if detail:report['detail']=detail[:400]
        return report
    try:
        vs,sdk,src,dest=map(_path,(vs_root,dia_sdk_root,source,out))
        if work_dir is not None:work_dir=_path(work_dir)
        receipt=dest.with_suffix(dest.suffix+'.build.json')
        if dest.exists() or receipt.exists() or dest.is_symlink() or receipt.is_symlink():return failed('build_destination_exists')
        if _has_link_or_reparse_component(dest.parent):return failed('build_destination_invalid')
        if os.name!='nt':return failed('windows_required')
        if (type(timeout) not in (int,float) or not 1<=timeout<=600 or type(memory_limit_mb) is not int
            or not 256<=memory_limit_mb<=8192):return failed('build_budget_invalid')
        version_file=vs/'VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt'
        if not _regular(version_file) or version_file.stat().st_size>4096:return failed('toolchain_version_file_invalid')
        with version_file.open('rb') as stream:version_bytes=stream.read(4097)
        if len(version_bytes)>4096:return failed('toolchain_version_file_invalid')
        version=version_bytes.decode('utf-8-sig').strip()
        if not re.fullmatch(r'\d{2}\.\d{2}\.\d{4,6}',version):return failed('toolchain_version_invalid')
        compiler_dir=vs/f'VC/Tools/MSVC/{version}/bin/Hostx64/x64'
        inputs={'version_file':version_file,'vcvars':vs/'VC/Auxiliary/Build/vcvarsall.bat',
            'compiler':compiler_dir/'cl.exe','linker':compiler_dir/'link.exe',
            'dia_header':sdk/'include/dia2.h','cvconst_header':sdk/'include/cvconst.h',
            'dia_guid_library':sdk/'lib/amd64/diaguids.lib'}
        for name,path in inputs.items():
            if not _regular(path) or path.stat().st_size>32*1024*1024:return failed('build_input_invalid',name)
        if not _regular(src):return failed('build_source_invalid')
        report.update(toolchain_version=version,output_path=str(dest),receipt_path=str(receipt),
            observed_inputs={name:dict(path=str(path),sha256=_hash(path)) for name,path in inputs.items()})
        report['observed_inputs']['version_file']['sha256']=hashlib.sha256(version_bytes).hexdigest()
        required=256*1024*1024+src.stat().st_size+sum(p.stat().st_size for p in inputs.values())
        parents=[work_dir] if work_dir is not None else [Path(tempfile.gettempdir()),Path.home()/'.aetherre/tmp']
        parent=None
        for candidate in parents:
            candidate=_path(candidate)
            if _has_link_or_reparse_component(candidate):continue
            existing=candidate
            while not existing.exists() and existing!=existing.parent:existing=existing.parent
            if shutil.disk_usage(existing).free>=required:
                candidate.mkdir(parents=True,exist_ok=True);parent=candidate;break
        if parent is None:return failed('build_disk_reserve_unavailable')
        job=Path(tempfile.mkdtemp(prefix='dia-build-',dir=parent));report['artifact_dir']=str(job)
        snapshots={}
        for key,path,name in [('source',src,'source.cpp'),('dia_header',inputs['dia_header'],'dia2.h'),
            ('cvconst_header',inputs['cvconst_header'],'cvconst.h'),('dia_guid_library',inputs['dia_guid_library'],'diaguids.lib')]:
            target=job/name
            expected=None if key=='source' else report['observed_inputs'][key]['sha256']
            digest=create_verified_snapshot(path,target,max_bytes=32*1024*1024,expected_sha256=expected)
            snapshots[key]=dict(path=str(target),sha256=digest)
        report['snapshots']=snapshots;report['source_sha256']=snapshots['source']['sha256']
        # All interpolated paths passed _path; generated names are constants.
        # Delayed expansion and AutoRun are disabled in both cmd invocations.
        script='\r\n'.join(['@echo off','chcp 65001 >nul','setlocal DisableDelayedExpansion',
            f'call "{inputs["vcvars"]}" x64 -vcvars_ver={version} >nul','if errorlevel 1 exit /b 1',
            f'"{inputs["compiler"]}" /nologo /EHsc /std:c++17 /I"{job}" /c source.cpp /Fo:source.obj',
            'if errorlevel 1 exit /b 1',
            f'"{inputs["linker"]}" /nologo source.obj /LIBPATH:"{job}" "{job / "diaguids.lib"}" ole32.lib oleaut32.lib /OUT:helper.exe',
            'if errorlevel 1 exit /b 1','exit /b 0',''])
        (job/'build.cmd').write_bytes(script.encode('utf-8'))
        env=os.environ.copy()
        for key in tuple(env):
            if key.upper() in {'CL','_CL_','LINK','_LINK_','ERRORLEVEL'}:env.pop(key)
        env.update(TEMP=str(job),TMP=str(job),VSCMD_SKIP_SENDTELEMETRY='1')
        system_root=Path(os.environ.get('SystemRoot',r'C:\Windows'))
        # cwd is passed through CreateProcess, not parsed by CMD. Keep /c's
        # command constant: CMD strips outer quotes around an absolute batch
        # path and can interpret metacharacters from a valid directory name.
        proc=run_bounded([str(system_root/'System32/cmd.exe'),'/d','/v:off','/c','build.cmd'],
            cwd=str(job),env=env,timeout=float(timeout),memory_limit_mb=memory_limit_mb,
            output_limit_bytes=2*1024*1024,require_process_tree=True)
        report['worker_execution']={k:v for k,v in proc.items() if k not in ('stdout','stderr')}
        (job/'stdout.log').write_text(proc.get('stdout',''),encoding='utf-8')
        (job/'stderr.log').write_text(proc.get('stderr',''),encoding='utf-8')
        report['stdout_sha256']=_hash(job/'stdout.log');report['stderr_sha256']=_hash(job/'stderr.log')
        for name,path in inputs.items():
            if not _regular(path) or _hash(path)!=report['observed_inputs'][name]['sha256']:return failed('build_input_changed',name)
        for name,item in snapshots.items():
            path=Path(item['path'])
            if not _regular(path) or _hash(path)!=item['sha256']:return failed('build_input_changed',name)
        report['original_source_changed']=not _regular(src) or _hash(src)!=report['source_sha256']
        if proc.get('timed_out'):return failed('compiler_timeout')
        if proc.get('resource_exceeded'):return failed('compiler_resource_exceeded')
        if proc.get('returncode')!=0:return failed('compiler_failed')
        if proc.get('capture_complete') is not True:return failed('compiler_capture_incomplete')
        if proc.get('process_tree_contained') is not True:return failed('compiler_tree_uncontained')
        helper=job/'helper.exe'
        if not _regular(helper) or not 2<helper.stat().st_size<=64*1024*1024:return failed('build_output_invalid')
        with helper.open('rb') as stream:
            if stream.read(2)!=b'MZ':return failed('build_output_invalid')
        dest.parent.mkdir(parents=True,exist_ok=True)
        report['helper_sha256']=create_verified_snapshot(helper,dest,max_bytes=64*1024*1024)
        report.update(status='complete',code='built',helper_published=True)
        staged_receipt=job/'build-receipt.json'
        staged_receipt.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
        create_verified_snapshot(staged_receipt,receipt,max_bytes=1024*1024)
        return report
    except (OSError,ValueError,TypeError,UnicodeError) as exc:
        return failed(str(exc) if str(exc)=='build_path_invalid' else 'build_execution_or_publication_failed',type(exc).__name__+':'+str(exc))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('vs-root','dia-sdk-root','source','out'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--work-dir');parser.add_argument('--timeout',type=int,default=120)
    args=parser.parse_args()
    report=build_dia_helper(**vars(args));print(json.dumps(report,ensure_ascii=False,indent=2))
    return 0 if report['status']=='complete' else 2


if __name__=='__main__':raise SystemExit(main())
