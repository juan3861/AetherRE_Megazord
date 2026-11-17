"""Independent known-layout PE fixtures for preferred static memory."""
import hashlib
import struct
import pytest
from aether_re.native_memory import build_pe_memory

def fixture():
    data=bytearray(1024);data[:2]=b'MZ';struct.pack_into('<I',data,60,128)
    data[128:132]=b'PE\0\0';struct.pack_into('<HHIIIHH',data,132,0x8664,1,0,0,0,240,0x2022)
    o=152;struct.pack_into('<H',data,o,0x20b);struct.pack_into('<Q',data,o+24,0x140000000)
    struct.pack_into('<II',data,o+32,4096,512);struct.pack_into('<II',data,o+56,8192,512)
    struct.pack_into('<I',data,o+108,16)
    s=o+240;data[s:s+8]=b'.data\0\0\0';struct.pack_into('<IIII',data,s+8,768,4096,512,512)
    struct.pack_into('<I',data,s+36,0xc0000040)
    data[512:1024]=bytes(i%251 for i in range(512));return data

def build(data):return build_pe_memory(bytes(data),target_sha256=hashlib.sha256(data).hexdigest(),space_id=0)

def directory(data,index,rva,size):struct.pack_into('<II',data,152+112+index*8,rva,size)

def test_preferred_pe_has_file_bss_and_unmapped_gaps():
    data=fixture();r=build(data)
    assert r['base']==0x140000000 and r['machine']==0x8664 and r['bits']==64
    assert r['bytes'][4096:4608]==data[512:1024]
    assert r['bytes'][4608:4864]==bytes(256)
    assert r['initialized'][4096:4864]==bytes([1])*768
    assert r['permissions'][4096:4864]==bytes([3])*768
    assert not any(r['initialized'][512:4096]) and not any(r['permissions'][512:4096])
    assert r['process_snapshot_proved'] is False and r['image_base_kind']=='preferred_vaddr'

def test_iat_bytes_are_quarantined_as_loader_unknown():
    data=fixture();directory(data,12,4104,16);r=build(data)
    assert r['initialized'][4104:4120]==bytes(16) and r['permissions'][4104:4120]==bytes(16)
    assert r['unknown_ranges'][0]['reason']=='import_address_table'

def test_relocation_target_is_unknown_and_not_silently_applied():
    data=fixture();directory(data,5,4096,12)
    struct.pack_into('<IIHH',data,512,4096,12,0xa010,0)
    r=build(data)
    assert r['initialized'][4112:4120]==bytes(8) and r['permissions'][4112:4120]==bytes(8)
    assert r['unknown_ranges'][0]['reason']=='base_relocation_target'

@pytest.mark.parametrize('offset,fmt,value',[(60,'I',999),(134,'H',97),(152,'H',0x107),(152+56,'I',2**30),
    (152+240+12,'I',256),(152+240+20,'I',900),(152+240+16,'I',1000),(152+32,'I',1)])
def test_malformed_pe_layout_is_rejected(offset,fmt,value):
    data=fixture();struct.pack_into('<'+fmt,data,offset,value)
    with pytest.raises(ValueError):build(data)

def test_unobserved_loader_contract_is_refused():
    for index in (9,10,13,14):
        data=fixture();directory(data,index,4096,64)
        with pytest.raises(ValueError):build(data)
    data=fixture();directory(data,1,4096,20)
    with pytest.raises(ValueError):build(data)

def test_invalid_relocation_and_iat_ranges_fail_closed():
    data=fixture();directory(data,5,4096,12);struct.pack_into('<IIHH',data,512,4096,7,0xa010,0)
    with pytest.raises(ValueError):build(data)

def test_import_first_thunk_must_be_covered_by_quarantined_iat():
    data=fixture();directory(data,1,4096,40);directory(data,12,4224,16)
    data[512:552]=bytes(40)
    struct.pack_into('<IIIII',data,512,0,0,0,4160,4192)
    struct.pack_into('<QQ',data,512+96,0x8000000000000001,0)
    with pytest.raises(ValueError,match='iat'):build(data)

def test_import_table_requires_termination_and_keeps_thunks_unknown():
    data=fixture();directory(data,1,4096,40);directory(data,12,4192,16)
    data[512:552]=bytes(40)
    struct.pack_into('<IIIII',data,512,0,0,0,4160,4192)
    struct.pack_into('<QQ',data,608,0x8000000000000001,0)
    r=build(data)
    assert r['initialized'][4192:4208]==bytes(16)
    directory(data,1,4096,20)
    with pytest.raises(ValueError,match='import'):build(data)
    data=fixture();directory(data,12,8000,8)
    with pytest.raises(ValueError):build(data)
