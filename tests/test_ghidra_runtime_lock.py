"""Independent small-file fixtures for the complete local runtime pin."""
import copy,hashlib,json,os
import subprocess
from pathlib import Path
import pytest


def roots(tmp_path):
    ghidra=tmp_path/'ghidra';jdk=tmp_path/'jdk'
    for root,name,data in [(ghidra,'Ghidra/Framework/Utility/lib/Utility.jar',b'utility'),
        (ghidra,'Ghidra/application.properties',b'application.version=fixture'),
        (ghidra,'support/analyzeHeadless.bat',b'launcher'),(jdk,'bin/java.exe',b'java'),
        (jdk,'release',b'fixture release'),(jdk,'lib/modules',b'transitive module')]:
        path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
    return ghidra,jdk


def api():
    from aether_re.ghidra_runtime_lock import build_ghidra_runtime_lock,verify_ghidra_runtime_lock
    return build_ghidra_runtime_lock,verify_ghidra_runtime_lock


def test_complete_reference_uses_actual_bytes_and_is_portable(tmp_path):
    build,verify=api();g,j=roots(tmp_path);lock=build(g,j)
    assert lock['schema']=='ghidra-runtime-lock.v1'
    assert set(lock['bundles'])=={'ghidra','jdk'}
    assert lock['bundles']['jdk']['files']['lib/modules']=={'bytes':17,'sha256':hashlib.sha256(b'transitive module').hexdigest()}
    assert str(tmp_path) not in json.dumps(lock)
    report=verify(lock,g,j);assert report['verified'] and report['errors']==[]
    assert report['file_count']==6 and report['total_bytes']==sum(p.stat().st_size for r in (g,j) for p in r.rglob('*') if p.is_file())
    assert not report['upstream_authenticity_proved'] and not report['continuous_execution_integrity_proved']


@pytest.mark.parametrize('mutation',['content','size','missing','extra'])
def test_transitive_changes_refuse_whole_bundle(tmp_path,mutation):
    build,verify=api();g,j=roots(tmp_path);lock=build(g,j);before=copy.deepcopy(lock);path=j/'lib/modules'
    if mutation=='content':path.write_bytes(b'TRANSITIVE MODULE')
    elif mutation=='size':path.write_bytes(b'x')
    elif mutation=='missing':path.unlink()
    else:(j/'lib/extra.dll').write_bytes(b'extra')
    report=verify(lock,g,j);assert not report['verified'] and report['errors']
    assert lock==before


@pytest.mark.parametrize('name',['../escape','/absolute','C:/absolute','a\\b','AUX','bad./x','a//b'])
def test_manifest_names_are_strict_before_filesystem_read(tmp_path,name):
    build,verify=api();g,j=roots(tmp_path);lock=build(g,j)
    lock['bundles']['jdk']['files'][name]={'bytes':1,'sha256':'0'*64}
    with pytest.raises(ValueError):verify(lock,g,j)


@pytest.mark.parametrize('field,value',[('bytes',True),('bytes',-1),('sha256','X'*64)])
def test_manifest_metadata_is_strict(tmp_path,field,value):
    build,verify=api();g,j=roots(tmp_path);lock=build(g,j)
    lock['bundles']['jdk']['files']['lib/modules'][field]=value
    with pytest.raises(ValueError):verify(lock,g,j)


def test_case_collision_rejected_in_manifest(tmp_path):
    build,verify=api();g,j=roots(tmp_path);lock=build(g,j)
    lock['bundles']['jdk']['files']['LIB/MODULES']=copy.deepcopy(lock['bundles']['jdk']['files']['lib/modules'])
    with pytest.raises(ValueError):verify(lock,g,j)


def test_hardlink_refused_even_with_same_content(tmp_path):
    build,_=api();g,j=roots(tmp_path);os.link(j/'release',j/'release-copy')
    with pytest.raises(ValueError):build(g,j)


def test_nested_roots_refused(tmp_path):
    build,_=api();g,j=roots(tmp_path)
    with pytest.raises(ValueError):build(g,g/'Ghidra')


def test_missing_runtime_essential_refused(tmp_path):
    build,_=api();g,j=roots(tmp_path);(j/'bin/java.exe').unlink()
    with pytest.raises(ValueError):build(g,j)


def test_unexpected_schema_fields_refused(tmp_path):
    build,verify=api();g,j=roots(tmp_path);lock=build(g,j);lock['trusted']=True
    with pytest.raises(ValueError):verify(lock,g,j)


def test_file_budget_is_enforced_before_hashing_large_file(tmp_path,monkeypatch):
    build,_=api();import aether_re.ghidra_runtime_lock as m
    g,j=roots(tmp_path);monkeypatch.setattr(m,'MAX_FILE_BYTES',4)
    with pytest.raises(ValueError):build(g,j)


def test_tree_mutation_during_read_refused(tmp_path,monkeypatch):
    build,_=api();g,j=roots(tmp_path);original=Path.open;changed=False
    def opening(path,*args,**kwargs):
        nonlocal changed
        if path==j/'lib/modules' and args and args[0]=='rb' and not changed:
            changed=True;(j/'lib/injected.dll').write_bytes(b'added while reading')
        return original(path,*args,**kwargs)
    monkeypatch.setattr(Path,'open',opening)
    with pytest.raises(ValueError):build(g,j)


def test_bounded_lock_reader_preserves_raw_and_canonical_identity(tmp_path):
    build,_=api();from aether_re.ghidra_runtime_lock import read_ghidra_runtime_lock,runtime_lock_bytes
    g,j=roots(tmp_path);lock=build(g,j);path=tmp_path/'lock.json';path.write_text(json.dumps(lock,indent=2),encoding='utf-8')
    read=read_ghidra_runtime_lock(path)
    assert read['manifest']==lock and read['raw_sha256']==hashlib.sha256(path.read_bytes()).hexdigest()
    assert runtime_lock_bytes(lock)==runtime_lock_bytes(json.loads(json.dumps(lock)))


def test_duplicate_json_key_refused(tmp_path):
    from aether_re.ghidra_runtime_lock import read_ghidra_runtime_lock
    path=tmp_path/'lock.json';path.write_text('{"schema":"a","schema":"b"}')
    with pytest.raises(ValueError,match='duplicate'):read_ghidra_runtime_lock(path)


def test_explicit_remote_roots_refuse_before_filesystem_access(tmp_path,monkeypatch):
    build,_=api();import aether_re.ghidra_runtime_lock as m
    monkeypatch.setattr(m,'_has_link_or_reparse_component',lambda path:pytest.fail('remote filesystem accessed'))
    with pytest.raises(ValueError,match='remote'):build(r'\\unreachable.invalid\share\ghidra',tmp_path/'jdk')


def test_hash_pin_detects_same_size_rewrite_with_restored_mtime(tmp_path):
    build,verify=api();g,j=roots(tmp_path);lock=build(g,j);path=j/'lib/modules';before=path.stat()
    path.write_bytes(b'TRANSITIVE MODULE');os.utime(path,ns=(before.st_atime_ns,before.st_mtime_ns))
    assert path.stat().st_size==before.st_size
    assert verify(lock,g,j)['verified'] is False


@pytest.mark.parametrize('limit',['MAX_FILES','MAX_TOTAL_BYTES','MAX_ENTRIES'])
def test_tree_budgets_cannot_be_exceeded(tmp_path,monkeypatch,limit):
    build,_=api();import aether_re.ghidra_runtime_lock as module
    g,j=roots(tmp_path);monkeypatch.setattr(module,limit,1)
    with pytest.raises(ValueError):build(g,j)


@pytest.mark.parametrize('change',['none','before','after','snapshot','postlink','prelink'])
def test_bridge_checks_exact_runtime_and_retains_both_reports(tmp_path,monkeypatch,change):
    build,_=api();import aether_re.ghidra_headless_bridge as bridge
    g,j=roots(tmp_path);lock=tmp_path/'lock.json';lock.write_text(json.dumps(build(g,j)),encoding='utf-8')
    target=tmp_path/'owned.bin';target.write_bytes(b'owned static input');called=[]
    if change=='before':(j/'lib/modules').write_bytes(b'changed before launch')
    if change=='prelink':os.link(j/'release',j/'release-copy')
    def bounded(command,**kwargs):
        called.append(command);out=Path(command[-1]);(out/'functions').mkdir()
        (out/'functions/f.c').write_text('int f(void){return 0;}')
        (out/'decompilation_summary.json').write_text(json.dumps(dict(schema='aetherre-ghidra-export.v2',target_sha256=hashlib.sha256(target.read_bytes()).hexdigest(),complete=True,total_functions=1,decompiled_functions=1,
            type_policy=dict(mode='observed_program_types',external_types_injected=False,legacy_type_injection_requested=False),functions=[dict(name='f',address='ram:401000',success=True,params=0,return_type='int',signature_source='ANALYSIS',signature='int f(void)',source_file='functions/f.c')])))
        if change=='after':(j/'lib/modules').write_bytes(b'changed during worker')
        if change=='postlink':os.link(j/'release',j/'release-copy')
        if change=='snapshot':(out.parent/'runtime-lock.json').write_bytes(b'{}')
        return dict(returncode=0,stdout='owned fake boundary',stderr='',timed_out=False,resource_exceeded=False,capture_complete=True,process_tree_contained=True)
    monkeypatch.setattr(bridge,'run_bounded',bounded)
    result=bridge.GhidraHeadlessBridge(g,j,runtime_lock=lock).decompile_binary(target,temp_work_dir=tmp_path/'jobs')
    assert result.success is (change=='none')
    assert len(called)==(0 if change in ('before','prelink') else 1)
    checks=result.worker_execution['runtime_lock'];assert checks['pre']['verified'] is (change not in ('before','prelink'))
    if change!='snapshot':assert Path(checks['snapshot_path']).read_bytes()==lock.read_bytes()
    if change not in ('before','prelink'):assert checks['post']['verified'] is (change=='none')
    directory=Path(result.artifact_dir);assert directory.is_dir()
    assert json.loads((directory/'runtime-verification.json').read_text())==checks
    if called:assert (directory/'worker-stdout.log').read_text()=='owned fake boundary'


@pytest.mark.parametrize('selection',['default','explicit'])
def test_pinned_default_alias_selects_physical_command_but_explicit_link_refuses(tmp_path,monkeypatch,selection):
    build,_=api();import aether_re.ghidra_headless_bridge as bridge
    g,j=roots(tmp_path);alias=tmp_path/'jdk-alias'
    made=subprocess.run(['cmd.exe','/d','/c','mklink','/J',str(alias),str(j)],capture_output=True,timeout=10)
    assert made.returncode==0,made.stderr
    lock=tmp_path/'lock.json';lock.write_text(json.dumps(build(g,j)))
    target=tmp_path/'owned.bin';target.write_bytes(b'owned');calls=[]
    def bounded(command,**options):
        calls.append(command)
        return dict(returncode=7,stdout='',stderr='deliberate worker failure',timed_out=False,resource_exceeded=False,capture_complete=True,process_tree_contained=True)
    monkeypatch.setattr(bridge,'run_bounded',bounded)
    monkeypatch.setattr(bridge.GhidraHeadlessBridge,'DEFAULT_GHIDRA_PATH',g)
    monkeypatch.setattr(bridge.GhidraHeadlessBridge,'DEFAULT_JDK_PATH',alias)
    backend=(bridge.GhidraHeadlessBridge(runtime_lock=lock) if selection=='default' else bridge.GhidraHeadlessBridge(g,alias,runtime_lock=lock))
    result=backend.decompile_binary(target,temp_work_dir=tmp_path/'jobs');checks=result.worker_execution['runtime_lock']
    assert not result.success
    if selection=='default':
        assert len(calls)==1 and calls[0][0]==str(j/'bin/java.exe')
        assert checks['pre']['verified'] and checks['post']['verified']
        assert checks['configured_roots']['jdk']==str(alias) and checks['pre']['roots']['jdk']==str(j.resolve())
    else:assert not calls and not checks['pre']['verified']
