"""A failed helper or unbound PDB must not become debug-type evidence."""
import hashlib,json
from pathlib import Path

import pytest

import aether_re.pdb_dia as dia

GUID='{12345678-1234-5678-1234-567812345678}'


def payload():
    return dict(schema=dia.SCHEMA,status='complete',guid=GUID,age=1,machine=34404,
        capabilities=['source_file','is_static'],symbols=[dict(name='narrow',rva=4096,length=4,sym_tag=5,sym_index=10,is_static=False,source_file='owned.c')],count=1,truncated=False)


def worker(raw=None,**changes):
    return dict(stdout=json.dumps(raw or payload()),stderr='',returncode=0,timed_out=False,resource_exceeded=False,
        capture_complete=True,process_tree_contained=True,**changes)


def inputs(tmp_path):
    paths=[]
    for name in ('owned.pdb','helper.exe','msdia140.dll'):
        path=tmp_path/name;path.write_bytes(('owned '+name).encode());paths.append(path)
    return paths


def typed_payload():
    raw=payload();raw['capabilities'].append('function_types');raw['symbols'][0]['function_type']=100
    base=dict(tag=16,name='',length=1,base_type=7,count=None,calling_convention=None,target=None,parameters=[],parameters_complete=True,opaque_layout=False)
    raw.update(types=[dict(id=100,tag=13,name='',length=None,base_type=None,count=1,calling_convention=0,target=101,parameters=[102],parameters_complete=True,opaque_layout=False),
        dict(base,id=101),dict(base,id=102,length=4)],type_count=3,type_edges=3,types_complete=True,enumeration_complete=True)
    return raw


@pytest.mark.parametrize('component', ['helper', 'dia_dll'])
@pytest.mark.parametrize('same_path', [False, True])
def test_analysis_target_cannot_be_launched_as_a_tool(tmp_path, monkeypatch, component, same_path):
    pdb, helper, dll = inputs(tmp_path)
    tool = helper if component == 'helper' else dll
    binary = tool if same_path else tmp_path / 'owned-target.exe'
    if not same_path:
        binary.write_bytes(tool.read_bytes())
    def forbidden(*args, **kwargs):
        pytest.fail('target bytes reached worker launch')
    monkeypatch.setattr(dia, 'run_bounded', forbidden)
    report = dia.extract_pdb_symbols(pdb, helper_path=helper, dia_dll=dll, binary_path=binary)
    assert report['status'] == 'unavailable'
    assert report['code'] == 'target_tool_alias'
    assert report['executed_target'] is False
    assert 'worker_execution' not in report


def test_typed_inventory_requires_explicit_enumeration_completion(tmp_path, monkeypatch):
    pdb, helper, dll = inputs(tmp_path)
    raw = typed_payload()
    del raw['enumeration_complete']
    monkeypatch.setattr(dia, 'run_bounded', lambda *a, **k: worker(raw))
    report = dia.extract_pdb_symbols(pdb, helper_path=helper, dia_dll=dll)
    assert report['status'] == 'unavailable'
    assert report['code'] == 'helper_enumeration_invalid'


@pytest.mark.parametrize('changes,code',[
    ({'returncode':7},'helper_failed'),({'capture_complete':False},'helper_capture_incomplete'),
    ({'process_tree_contained':False},'helper_tree_uncontained'),
])
def test_failed_or_incomplete_worker_never_reports_complete(tmp_path,monkeypatch,changes,code):
    pdb,helper,dll=inputs(tmp_path);r=worker();r.update(changes)
    monkeypatch.setattr(dia,'run_bounded',lambda *a,**k:r)
    report=dia.extract_pdb_symbols(pdb,helper_path=helper,dia_dll=dll)
    assert report['status']=='unavailable' and report['code']==code
    assert report['worker_execution']['returncode']==r['returncode']


def test_worker_reads_private_snapshots_and_hashes_captured_bytes(tmp_path,monkeypatch):
    pdb,helper,dll=inputs(tmp_path);digest=hashlib.sha256(pdb.read_bytes()).hexdigest();seen=[]
    def fake(command,**kwargs):
        seen.append(kwargs)
        assert Path(command[0])!=helper and Path(command[1])!=dll and Path(command[2])!=pdb
        assert hashlib.sha256(Path(command[2]).read_bytes()).hexdigest()==digest
        pdb.write_bytes(b'changed after snapshot')
        return worker()
    monkeypatch.setattr(dia,'run_bounded',fake)
    report=dia.extract_pdb_symbols(pdb,helper_path=helper,dia_dll=dll)
    assert report['status']=='complete' and report['pdb_sha256']==digest
    assert seen[0]['require_process_tree'] is True and seen[0]['output_limit_bytes']>0


@pytest.mark.parametrize('mutation',[
    lambda d:d.update(count=2),lambda d:d.update(count=True),
    lambda d:d['symbols'][0].update(rva=-1),lambda d:d.update(guid='bad'),
    lambda d:d['symbols'].append(dict(d['symbols'][0])),
    lambda d:d['symbols'][0].update(sym_tag=7),lambda d:d['symbols'][0].pop('sym_tag'),
    lambda d:d['symbols'][0].update(sym_index=-1),lambda d:d['symbols'][0].update(sym_index=2**32),
    lambda d:d['symbols'][0].update(is_static='false'),lambda d:d['symbols'][0].update(source_file=[]),
    lambda d:d.update(capabilities={}),lambda d:d.update(binary_equivalence_proved=True),
])
def test_inventory_and_identity_contradictions_are_refused(tmp_path,monkeypatch,mutation):
    pdb,helper,dll=inputs(tmp_path);raw=payload();mutation(raw)
    monkeypatch.setattr(dia,'run_bounded',lambda *a,**k:worker(raw))
    assert dia.extract_pdb_symbols(pdb,helper_path=helper,dia_dll=dll)['status']=='unavailable'


def test_duplicate_json_keys_cannot_override_failed_status(tmp_path,monkeypatch):
    pdb,helper,dll=inputs(tmp_path);r=worker();r['stdout']=r['stdout'].replace('"status": "complete"','"status":"error","status":"complete"')
    monkeypatch.setattr(dia,'run_bounded',lambda *a,**k:r)
    assert dia.extract_pdb_symbols(pdb,helper_path=helper,dia_dll=dll)['status']=='unavailable'


def test_private_snapshot_cannot_be_replaced_with_equal_hash_hardlink(tmp_path,monkeypatch):
    import os
    pdb,helper,dll=inputs(tmp_path)
    replaced=[]
    def fake(command,**kwargs):
        snapshot=Path(command[2]);snapshot.unlink();os.link(pdb,snapshot)
        replaced.append(snapshot.stat().st_nlink)
        return worker()
    monkeypatch.setattr(dia,'run_bounded',fake)
    # The adversarial replacement must actually happen, even when the host's
    # default temporary directory is on a different volume from pytest.
    report=dia.extract_pdb_symbols(pdb,helper_path=helper,dia_dll=dll,temp_work_dir=tmp_path/'private')
    assert replaced and replaced[0]>=2
    assert report['status']=='unavailable' and report['code']=='private_snapshot_changed'


@pytest.mark.parametrize('mutation',[
    lambda d:d['types'][0].update(target=999),lambda d:d.update(type_count=4),
    lambda d:d['types'].append(dict(d['types'][0])),lambda d:d['symbols'][0].update(function_type=101),
    lambda d:d['types'][0].update(parameters=[999]),lambda d:d['types'][1].update(length=-1),
    lambda d:d.update(types_complete=True,type_edges=1),lambda d:d['types'][0].update(parameters_complete=False),
    lambda d:d['types'][1].update(tag=999),lambda d:d['types'][1].update(base_type=999),
    lambda d:d['types'][1].update(length=None),lambda d:d['types'][1].update(base_type=None),
    lambda d:d['types'][0].update(target=100),lambda d:d['types'][1].update(target=101),
])
def test_type_graph_contradictions_never_become_complete(tmp_path,monkeypatch,mutation):
    pdb,helper,dll=inputs(tmp_path);raw=typed_payload();mutation(raw)
    monkeypatch.setattr(dia,'run_bounded',lambda *a,**k:worker(raw))
    assert dia.extract_pdb_symbols(pdb,helper_path=helper,dia_dll=dll)['status']=='unavailable'


def test_partial_type_graph_has_explicit_denominator_and_no_recovery_claim(tmp_path,monkeypatch):
    pdb,helper,dll=inputs(tmp_path);raw=typed_payload();raw['types_complete']=False
    monkeypatch.setattr(dia,'run_bounded',lambda *a,**k:worker(raw))
    report=dia.extract_pdb_symbols(pdb,helper_path=helper,dia_dll=dll)
    assert report['status']=='partial' and report['type_coverage']['functions_with_signature']==1
    assert report['binary_equivalence_proved'] is False and report['type_recovery_proved'] is False


def test_return_contract_requires_bound_target_unique_rva_and_scalar_type(tmp_path,monkeypatch):
    pdb,helper,dll=inputs(tmp_path);raw=typed_payload();binary=tmp_path/'owned.exe';binary.write_bytes(b'own PE')
    monkeypatch.setattr(dia,'parse_pe_codeview',lambda b:dict(status='complete',machine=34404,records=[dict(guid=GUID,age=1)]))
    monkeypatch.setattr(dia,'run_bounded',lambda *a,**k:worker(raw))
    report=dia.extract_pdb_symbols(pdb,helper_path=helper,dia_dll=dll,binary_path=binary)
    digest=hashlib.sha256(binary.read_bytes()).hexdigest()
    contract=dia.pdb_return_contract(report,target_sha256=digest,function_rva=4096)
    assert contract['return_bits']==8 and contract['signed'] is False and contract['type_id']==101
    with pytest.raises(ValueError):dia.pdb_return_contract(report,target_sha256='f'*64,function_rva=4096)
    with pytest.raises(ValueError):dia.pdb_return_contract(report,target_sha256=digest,function_rva=8192)
    report['types'][1]['length']=8
    with pytest.raises(ValueError,match='payload_changed'):dia.pdb_return_contract(report,target_sha256=digest,function_rva=4096)


def test_return_binding_metadata_cannot_change_after_validation(tmp_path,monkeypatch):
    pdb,helper,dll=inputs(tmp_path);binary=tmp_path/'own.exe';binary.write_bytes(b'own')
    monkeypatch.setattr(dia,'parse_pe_codeview',lambda b:dict(status='complete',machine=34404,records=[dict(guid=GUID,age=1)]))
    monkeypatch.setattr(dia,'run_bounded',lambda *a,**k:worker(typed_payload()))
    report=dia.extract_pdb_symbols(pdb,helper_path=helper,dia_dll=dll,binary_path=binary)
    report['binary_sha256']='f'*64;report['binding']['binary_sha256']='f'*64
    with pytest.raises(ValueError,match='payload_changed'):dia.pdb_return_contract(report,target_sha256='f'*64,function_rva=4096)
