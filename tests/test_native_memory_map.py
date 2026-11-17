"""File-backed bytes require explicit provenance; gaps remain unknown."""
import hashlib
import pytest

from aether_re.native_memory import build_file_memory

DATA=b'abcdefgh'
HASH=hashlib.sha256(DATA).hexdigest()

def region(**changes):
    return dict(dict(address=4096,file_offset=1,file_size=3,memory_size=5,permissions='RW',zero_fill=False),**changes)

def build(regions,**changes):
    return build_file_memory(DATA,**dict(dict(target_sha256=HASH,base=4096,space_id=0,regions=regions),**changes))

def test_file_bytes_tail_and_gap_have_distinct_provenance():
    result=build([region(),region(address=4104,file_offset=6,file_size=2,memory_size=2)])
    assert result['bytes']==b'bcd'+bytes(5)+b'gh'
    assert result['initialized']==bytes([1,1,1,0,0,0,0,0,1,1])
    assert result['permissions']==bytes([3]*5+[0]*3+[3]*2)
    assert result['target_sha256']==HASH and result['process_snapshot_proved'] is False
    assert result['provenance'][0]['file_offset']==1

def test_zero_fill_is_an_explicit_hypothesis():
    result=build([region(zero_fill=True)])
    assert result['bytes']==b'bcd\0\0' and result['initialized']==bytes([1]*5)
    assert 'declared_zero_fill' in result['hypotheses']

@pytest.mark.parametrize('changes',[
    dict(file_offset=7,file_size=2),dict(address=4095),dict(memory_size=2),
    dict(memory_size=1048577),dict(file_size=True),dict(permissions='Q'),dict(zero_fill=1),
])
def test_malformed_regions_are_rejected(changes):
    with pytest.raises(ValueError):build([region(**changes)])

def test_hash_mismatch_and_overlapping_regions_fail_closed():
    with pytest.raises(ValueError):build([region()],target_sha256='0'*64)
    with pytest.raises(ValueError):build([region(),region(address=4098)])
    with pytest.raises(ValueError):build([region(address=2**64-1)],base=2**64-1)
