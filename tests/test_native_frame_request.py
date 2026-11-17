import copy,hashlib,runpy
from pathlib import Path
import pytest


def api():
    from aether_re import native_frame_request
    return native_frame_request


def inputs(tmp_path):
    language=runpy.run_path(str(Path(__file__).with_name('test_native_frame_address.py')))['LANGUAGE']
    target=tmp_path/'owned.bin';target.write_bytes(b'owned stable input bytes')
    directory=tmp_path/'language';directory.mkdir()
    for name,raw in language.items():(directory/name).write_bytes(raw)
    return target,directory,language


def test_request_trio_and_disabled_default():
    assert api().validate_native_frame_request(None,None,None) is None
    assert api().validate_native_frame_request('root',16,'language') is None


@pytest.mark.parametrize('selector,extent,directory',[(None,16,'language'),('root',None,'language'),('root',16,None),
    (True,16,'language'),('',16,'language'),('root',True,'language'),('root',0,'language'),('root',4097,'language'),('root',16,False)])
def test_invalid_request_refuses_without_io(selector,extent,directory):
    with pytest.raises(ValueError):api().validate_native_frame_request(selector,extent,directory)


@pytest.mark.parametrize('option',['derive_frame_function','frame_fact','reconstruct_function','memory_model','memory_derivation',
                                  'call_model','debug_pdb','dia_helper','dia_dll'])
def test_incompatible_options_refuse(option):
    with pytest.raises(ValueError):api().validate_native_frame_request('root',16,'language',**{option:'supplied'})


def test_stable_reads_preserve_all_bytes_and_do_not_claim_authenticity(tmp_path):
    target,directory,language=inputs(tmp_path);packet=api().read_native_frame_inputs(target,directory)
    assert packet['target_bytes']==target.read_bytes() and packet['language_sources']==language
    assert packet['target_path']==str(target)
    receipt=packet['receipt'];assert receipt['target']['sha256']==hashlib.sha256(target.read_bytes()).hexdigest()
    assert receipt['target_executed'] is False and receipt['language_toolchain_authenticity_proved'] is False
    for name,raw in language.items():assert receipt['language_sources'][name]['sha256']==hashlib.sha256(raw).hexdigest()


def test_snapshots_preserve_original_bytes_and_original_paths(tmp_path):
    target,directory,language=inputs(tmp_path);packet=api().read_native_frame_inputs(target,directory);before=copy.deepcopy(packet)
    destination=tmp_path/'snapshot'
    captured=api().snapshot_native_frame_inputs(packet,destination,expected_target_sha256=packet['receipt']['target']['sha256'])
    assert captured['target_path']==str(destination/'target.bin')
    assert captured['target_bytes']==packet['target_bytes'] and captured['language_sources']==language
    assert (destination/'target.bin').read_bytes()==target.read_bytes()
    assert captured['receipt']['target']['path']==str(target)
    assert captured['receipt']['target']['snapshot_path']==str(destination/'target.bin')
    for name,raw in language.items():
        assert (destination/name).read_bytes()==raw
        assert captured['receipt']['language_sources'][name]['path']==str(directory/name)
        assert captured['receipt']['language_sources'][name]['snapshot_path']==str(destination/name)
    assert packet==before
    with pytest.raises((ValueError,FileExistsError)):api().snapshot_native_frame_inputs(packet,destination)
    assert (destination/'target.bin').read_bytes()==target.read_bytes()


@pytest.mark.parametrize('part',['target','language'])
def test_changed_source_after_preflight_refuses_without_overwriting(tmp_path,part):
    target,directory,_=inputs(tmp_path);packet=api().read_native_frame_inputs(target,directory)
    changed=target if part=='target' else directory/'ia.sinc';changed.write_bytes(changed.read_bytes()+b' ')
    with pytest.raises(ValueError):api().snapshot_native_frame_inputs(packet,tmp_path/'snapshot')
    if part=='target':assert not (tmp_path/'snapshot/target.bin').exists()
    else:assert not (tmp_path/'snapshot/ia.sinc').exists()


def test_target_binding_and_packet_hash_mismatch_refuse_before_snapshot(tmp_path):
    target,directory,_=inputs(tmp_path);packet=api().read_native_frame_inputs(target,directory)
    with pytest.raises(ValueError):api().snapshot_native_frame_inputs(packet,tmp_path/'wrong-target',expected_target_sha256='0'*64)
    assert not (tmp_path/'wrong-target').exists()
    packet['target_bytes']+=b' '
    with pytest.raises(ValueError):api().snapshot_native_frame_inputs(packet,tmp_path/'forged')
    assert not (tmp_path/'forged').exists()


@pytest.mark.parametrize('part',['target','language','directory'])
def test_budgets_or_nonregular_sources_refuse(tmp_path,part):
    target,directory,_=inputs(tmp_path)
    if part=='directory':
        path=directory/'ia.sinc';path.unlink();path.mkdir()
    else:
        path=target if part=='target' else directory/'ia.sinc'
        with path.open('wb') as handle:handle.truncate((32 if part=='target' else 4)*1024**2+1)
    with pytest.raises(ValueError):api().read_native_frame_inputs(target,directory)


def test_unsafe_parent_is_refused_before_creating_snapshot_directory(tmp_path,monkeypatch):
    from aether_re import evidence
    target,directory,_=inputs(tmp_path);packet=api().read_native_frame_inputs(target,directory)
    parent=tmp_path/'alias-parent';parent.mkdir();destination=parent/'snapshot'
    original=evidence._is_link_or_reparse_point
    monkeypatch.setattr(evidence,'_is_link_or_reparse_point',lambda path:Path(path)==parent or original(path))
    with pytest.raises(ValueError):api().snapshot_native_frame_inputs(packet,destination)
    assert not destination.exists()
