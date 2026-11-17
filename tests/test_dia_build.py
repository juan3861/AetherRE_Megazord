"""The published DIA build must use the configured toolchain and preserve evidence."""
import hashlib
import json
from pathlib import Path

import pytest

from aether_re import dia_build as build


def setup_inputs(tmp_path):
    vs=tmp_path/'VS tools';sdk=tmp_path/'DIA SDK';source=tmp_path/'own.cpp';source.write_text('int main(){return 0;}')
    files={
        vs/'VC/Auxiliary/Build/vcvarsall.bat':'@echo off',
        vs/'VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt':'14.99.12345\n',
        vs/'VC/Tools/MSVC/14.99.12345/bin/Hostx64/x64/cl.exe':'owned compiler fixture',
        vs/'VC/Tools/MSVC/14.99.12345/bin/Hostx64/x64/link.exe':'owned linker fixture',
        sdk/'include/dia2.h':'owned header',sdk/'include/cvconst.h':'owned constants',
        sdk/'lib/amd64/diaguids.lib':'owned library',
    }
    for p,text in files.items():p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
    return dict(vs_root=vs,dia_sdk_root=sdk,source=source,out=tmp_path/'published/helper.exe',work_dir=tmp_path/'jobs')


def worker(command,**kwargs):
    job=Path(kwargs['cwd']);(job/'helper.exe').write_bytes(b'MZown built helper')
    return dict(returncode=0,stdout='own compiler output',stderr='',timed_out=False,resource_exceeded=False,capture_complete=True,process_tree_contained=True)


def test_configured_default_version_and_private_compile_are_recorded(tmp_path,monkeypatch):
    args=setup_inputs(tmp_path);calls=[]
    monkeypatch.setenv('CL','/DUNTRUSTED');monkeypatch.setenv('_LINK_','/OUT:wrong.exe');monkeypatch.setenv('ERRORLEVEL','0')
    def fake(command,**kwargs):
        calls.append((command,kwargs));job=Path(kwargs['cwd'])
        assert job!=Path.cwd() and job.is_relative_to(args['work_dir'])
        assert (job/'source.cpp').read_bytes()==args['source'].read_bytes()
        script=(job/'build.cmd').read_text(encoding='utf-8')
        assert '14.99.12345' in script and '14.50.35717' not in script
        assert str(args['vs_root']/'VC/Tools/MSVC/14.99.12345/bin/Hostx64/x64/cl.exe') in script
        assert 'CL' not in kwargs['env'] and '_LINK_' not in kwargs['env']
        assert 'ERRORLEVEL' not in kwargs['env'] and '%errorlevel%' not in script.lower()
        assert kwargs['require_process_tree'] is True and kwargs['output_limit_bytes']>0
        return worker(command,**kwargs)
    monkeypatch.setattr(build,'run_bounded',fake)
    report=build.build_dia_helper(**args)
    assert report['status']=='complete' and report['toolchain_version']=='14.99.12345' and len(calls)==1
    assert report['helper_sha256']==hashlib.sha256(args['out'].read_bytes()).hexdigest()
    receipt=json.loads(args['out'].with_suffix('.exe.build.json').read_text(encoding='utf-8'))
    assert receipt['helper_sha256']==report['helper_sha256'] and receipt['hermetic_build_proved'] is False
    assert not (Path.cwd()/'source.obj').exists()


@pytest.mark.parametrize('change,code',[
    ({'returncode':1},'compiler_failed'),({'capture_complete':False},'compiler_capture_incomplete'),
    ({'process_tree_contained':False},'compiler_tree_uncontained'),({'timed_out':True},'compiler_timeout'),
    ({'resource_exceeded':True},'compiler_resource_exceeded'),
])
def test_failed_worker_cannot_publish_success(tmp_path,monkeypatch,change,code):
    args=setup_inputs(tmp_path)
    def fake(command,**kwargs):result=worker(command,**kwargs);result.update(change);return result
    monkeypatch.setattr(build,'run_bounded',fake)
    report=build.build_dia_helper(**args)
    assert report['status']=='unavailable' and report['code']==code
    assert not args['out'].exists()


@pytest.mark.parametrize('kind',['exe','receipt'])
def test_previous_output_is_preserved_before_worker(tmp_path,monkeypatch,kind):
    args=setup_inputs(tmp_path);old=args['out'] if kind=='exe' else args['out'].with_suffix('.exe.build.json')
    old.parent.mkdir();old.write_bytes(b'prior evidence')
    monkeypatch.setattr(build,'run_bounded',lambda *a,**k:pytest.fail('existing destination reached compiler'))
    report=build.build_dia_helper(**args)
    assert report['status']=='unavailable' and report['code']=='build_destination_exists'
    assert old.read_bytes()==b'prior evidence'


@pytest.mark.parametrize('invalid',['%INJECT%','bad\npath','bad\rpath','bad"path','caret^part'])
def test_cmd_paths_cannot_introduce_expansion_or_commands(tmp_path,monkeypatch,invalid):
    args=setup_inputs(tmp_path);args['vs_root']=tmp_path/invalid
    monkeypatch.setattr(build,'run_bounded',lambda *a,**k:pytest.fail('unsafe path reached compiler'))
    report=build.build_dia_helper(**args)
    assert report['status']=='unavailable' and report['code']=='build_path_invalid'


@pytest.mark.parametrize('version',['../escape','14.44 & whoami','', '14.44\n14.45'])
def test_default_version_is_a_validated_identity(tmp_path,monkeypatch,version):
    args=setup_inputs(tmp_path)
    (args['vs_root']/'VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt').write_text(version)
    monkeypatch.setattr(build,'run_bounded',lambda *a,**k:pytest.fail('invalid version reached compiler'))
    assert build.build_dia_helper(**args)['code']=='toolchain_version_invalid'


@pytest.mark.parametrize('mutation',['snapshot','compiler','header','missing_output'])
def test_changed_inputs_or_absent_output_cannot_publish(tmp_path,monkeypatch,mutation):
    args=setup_inputs(tmp_path)
    def fake(command,**kwargs):
        result=worker(command,**kwargs);job=Path(kwargs['cwd'])
        target={'snapshot':job/'source.cpp','compiler':args['vs_root']/'VC/Tools/MSVC/14.99.12345/bin/Hostx64/x64/cl.exe',
            'header':args['dia_sdk_root']/'include/dia2.h','missing_output':job/'helper.exe'}[mutation]
        if mutation=='missing_output':target.unlink()
        else:target.write_bytes(b'changed during compilation')
        return result
    monkeypatch.setattr(build,'run_bounded',fake)
    report=build.build_dia_helper(**args)
    assert report['status']=='unavailable' and not args['out'].exists()
    assert report['code']=='build_output_invalid' if mutation=='missing_output' else report['code']=='build_input_changed'


def test_changed_original_source_is_distinct_from_private_compiled_source(tmp_path,monkeypatch):
    args=setup_inputs(tmp_path);original=args['source'].read_bytes()
    def fake(command,**kwargs):args['source'].write_bytes(b'new source after capture');return worker(command,**kwargs)
    monkeypatch.setattr(build,'run_bounded',fake)
    report=build.build_dia_helper(**args)
    assert report['status']=='complete'
    assert report['source_sha256']==hashlib.sha256(original).hexdigest()
    assert report['original_source_changed'] is True


@pytest.mark.parametrize('options',[
    dict(timeout=0),dict(timeout=True),dict(timeout=float('nan')),dict(timeout=601),
    dict(memory_limit_mb=255),dict(memory_limit_mb=True),dict(memory_limit_mb=8193),
])
def test_invalid_build_budget_is_refused_before_compiler(tmp_path,monkeypatch,options):
    args=setup_inputs(tmp_path)
    monkeypatch.setattr(build,'run_bounded',lambda *a,**k:pytest.fail('invalid budget reached compiler'))
    assert build.build_dia_helper(**args,**options)['code']=='build_budget_invalid'


def test_receipt_publication_failure_is_not_reported_as_complete(tmp_path,monkeypatch):
    args=setup_inputs(tmp_path);monkeypatch.setattr(build,'run_bounded',worker)
    original=build.create_verified_snapshot
    def publish(source,dest,**kwargs):
        if Path(dest)==args['out'].with_suffix('.exe.build.json'):raise OSError('injected disk full at receipt')
        return original(source,dest,**kwargs)
    monkeypatch.setattr(build,'create_verified_snapshot',publish)
    report=build.build_dia_helper(**args)
    assert report['status']=='unavailable' and report['code']=='build_execution_or_publication_failed'
    assert report['helper_published'] is True and args['out'].read_bytes()==b'MZown built helper'
    assert not args['out'].with_suffix('.exe.build.json').exists()


def test_explicit_work_directory_requires_disk_reserve(tmp_path,monkeypatch):
    args=setup_inputs(tmp_path)
    from collections import namedtuple
    usage=namedtuple('Usage','total used free')
    monkeypatch.setattr(build.shutil,'disk_usage',lambda p:usage(100,100,0))
    monkeypatch.setattr(build,'run_bounded',lambda *a,**k:pytest.fail('no reserve reached compiler'))
    assert build.build_dia_helper(**args)['code']=='build_disk_reserve_unavailable'


def test_cmd_entrypoint_is_constant_not_a_shell_parsed_work_path(tmp_path,monkeypatch):
    args=setup_inputs(tmp_path);args['work_dir']=tmp_path/'amp&echo OWN_MARKER&rem'
    def fake(command,**kwargs):
        assert command[-1]=='build.cmd'
        assert str(kwargs['cwd']) not in command[-1]
        return worker(command,**kwargs)
    monkeypatch.setattr(build,'run_bounded',fake)
    assert build.build_dia_helper(**args)['status']=='complete'


def test_sdk_snapshot_must_match_preobserved_input_identity(tmp_path,monkeypatch):
    args=setup_inputs(tmp_path);monkeypatch.setattr(build,'run_bounded',worker)
    original=build.create_verified_snapshot
    header=args['dia_sdk_root']/'include/dia2.h';before=header.read_bytes()
    def capture(source,dest,**kwargs):
        if Path(source)==header:
            header.write_bytes(b'different SDK bytes at capture')
            try:return original(source,dest,**kwargs)
            finally:header.write_bytes(before)
        return original(source,dest,**kwargs)
    monkeypatch.setattr(build,'create_verified_snapshot',capture)
    report=build.build_dia_helper(**args)
    assert report['status']=='unavailable' and not args['out'].exists()


def test_selected_version_is_bound_to_the_bytes_that_were_parsed(tmp_path,monkeypatch):
    args=setup_inputs(tmp_path);monkeypatch.setattr(build,'run_bounded',worker)
    version=args['vs_root']/'VC/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt'
    from contextlib import contextmanager
    original=Path.open;changed=[]
    @contextmanager
    def opening(path,*args,**kwargs):
        with original(path,*args,**kwargs) as stream:yield stream
        mode=args[0] if args else kwargs.get('mode','r')
        if path==version and 'r' in mode and not changed:
            changed.append(True)
            with original(version,'w',encoding='utf-8') as stream:stream.write('14.98.12345\n')
    monkeypatch.setattr(Path,'open',opening)
    report=build.build_dia_helper(**args)
    assert changed and report['status']=='unavailable' and not args['out'].exists()


@pytest.mark.parametrize('shadow',[None,'0','23'])
def test_real_cmd_rejects_failed_vcvars_even_with_errorlevel_shadow(tmp_path,monkeypatch,shadow):
    args=setup_inputs(tmp_path)
    (args['vs_root']/'VC/Auxiliary/Build/vcvarsall.bat').write_text('@echo off\nexit /b 7\n')
    if shadow is None:monkeypatch.delenv('ERRORLEVEL',raising=False)
    else:monkeypatch.setenv('ERRORLEVEL',shadow)
    report=build.build_dia_helper(**args)
    assert report['status']=='unavailable' and report['code']=='compiler_failed'
    assert report['worker_execution']['returncode']!=0 and not args['out'].exists()
