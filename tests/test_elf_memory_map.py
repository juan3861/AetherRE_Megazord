"""ELF program-header maps and loader-unknown cells, no file execution."""
import hashlib,struct
import pytest
from aether_re.native_memory import build_elf_memory

def fixture(bits=64,dynamic=False):
    data=bytearray(1024);data[:7]=b'\x7fELF'+bytes([2 if bits==64 else 1,1,1])
    count=3 if dynamic else 2;header=64 if bits==64 else 52;phsize=56 if bits==64 else 32
    if bits==64:
        struct.pack_into('<HHIQQQIHHHHHH',data,16,3,62,1,0x400100,header,0,0,header,phsize,count,0,0,0)
    else:struct.pack_into('<HHIIIIIHHHHHH',data,16,3,3,1,0x400100,header,0,0,header,phsize,count,0,0,0)
    def ph(index,kind,flags,offset,address,filesz,memsz,align):
        if bits==64:struct.pack_into('<IIQQQQQQ',data,header+index*phsize,kind,flags,offset,address,address,filesz,memsz,align)
        else:struct.pack_into('<IIIIIIII',data,header+index*phsize,kind,offset,address,address,filesz,memsz,flags,align)
    ph(0,1,5,0,0x400000,768,768,4096);ph(1,1,6,768,0x401300,256,384,4096)
    data[768:1024]=bytes(i%251 for i in range(256))
    if dynamic:
        ph(2,2,6,512,0x400200,128,128,8)
        entries=[(7,0x400280),(8,24),(9,24),(21,0),(0,0)] if bits==64 else [(17,0x400280),(18,8),(19,8),(21,0),(0,0)]
        for i,(tag,value) in enumerate(entries):struct.pack_into('<qQ' if bits==64 else '<iI',data,512+i*(16 if bits==64 else 8),tag,value)
        if bits==64:struct.pack_into('<QQq',data,640,0x401320,8,0)
        else:struct.pack_into('<II',data,640,0x401320,8)
    return data

def build(data):return build_elf_memory(bytes(data),target_sha256=hashlib.sha256(data).hexdigest(),space_id=0)

@pytest.mark.parametrize('bits',[32,64])
def test_segments_preserve_file_zero_fill_and_unknown_gaps(bits):
    data=fixture(bits);r=build(data)
    assert r['base']==0x400000 and r['bits']==bits
    assert r['bytes'][0x1300:0x1400]==data[768:1024] and r['bytes'][0x1400:0x1480]==bytes(128)
    assert r['initialized'][0x1300:0x1480]==bytes([1])*384
    assert not any(r['permissions'][768:0x1300]) and not any(r['initialized'][768:0x1300])
    assert r['image_base_kind']=='link_vaddr' and r['process_snapshot_proved'] is False

@pytest.mark.parametrize('bits',[32,64])
def test_dynamic_relocations_and_debug_pointer_are_unknown(bits):
    r=build(fixture(bits,True));width=bits//8
    assert r['initialized'][0x1320:0x1320+width]==bytes(width)
    debug=512+3*(16 if bits==64 else 8)+width
    assert r['permissions'][debug:debug+width]==bytes(width)
    assert {x['reason'] for x in r['unknown_ranges']}=={'dynamic_debug_pointer','dynamic_relocation_target'}

@pytest.mark.parametrize('offset,fmt,value',[(5,'B',2),(18,'H',0),(54,'H',2),(56,'H',65535),
    (64+32,'Q',769),(64+40,'Q',1),(64+48,'Q',3),(64+56+16,'Q',0x400100)])
def test_invalid_layouts_reject_before_materialization(offset,fmt,value):
    data=fixture();struct.pack_into('<'+fmt,data,offset,value)
    with pytest.raises(ValueError):build(data)

def test_dynamic_requires_termination_and_supported_rel_types():
    data=fixture(dynamic=True);struct.pack_into('<QQq',data,640,0x401320,5,0)
    with pytest.raises(ValueError,match='relocation'):build(data)
    data=fixture(dynamic=True)
    for i in range(8):struct.pack_into('<qQ',data,512+16*i,1,i)
    with pytest.raises(ValueError,match='dynamic'):build(data)

def test_dynamic_header_cannot_disagree_with_load_file_mapping():
    data=fixture(dynamic=True);struct.pack_into('<Q',data,64+2*56+8,528)
    with pytest.raises(ValueError):build(data)

def test_sparse_map_preserves_far_apart_addresses_without_allocating_holes():
    data=fixture();struct.pack_into('<Q',data,64+56+16,0x600300)
    with pytest.raises(ValueError,match='budget'):build(data)
    r=build_elf_memory(bytes(data),target_sha256=hashlib.sha256(data).hexdigest(),space_id=0,sparse=True)
    assert r['schema']=='sparse-linked-elf-memory.v1' and 'bytes' not in r
    assert [m['base'] for m in r['regions']]==[0x400000,0x600300]
    assert sum(len(m['bytes']) for m in r['regions'])==1152
    assert r['regions'][1]['bytes'][:256]==data[768:1024]
    assert r['contiguous_runtime_compatible'] is False

def test_sparse_relocations_mask_original_virtual_address():
    data=fixture(dynamic=True);struct.pack_into('<Q',data,64+56+16,0x600300)
    struct.pack_into('<QQq',data,640,0x600320,8,0)
    r=build_elf_memory(bytes(data),target_sha256=hashlib.sha256(data).hexdigest(),space_id=0,sparse=True)
    assert r['regions'][1]['initialized'][32:40]==bytes(8)
    assert r['regions'][0]['permissions'][568:576]==bytes(8)

@pytest.mark.parametrize('bits',[32,64])
@pytest.mark.parametrize('count,relocation',[(2,8),(1,1)])
def test_optimized_relative_count_must_fit_table_and_relative_prefix(count,relocation,bits):
    data=fixture(bits,dynamic=True)
    struct.pack_into('<qQ' if bits==64 else '<iI',data,512+3*(16 if bits==64 else 8),0x6ffffff9 if bits==64 else 0x6ffffffa,count)
    if bits==64:struct.pack_into('<QQq',data,640,0x401320,relocation,0)
    else:struct.pack_into('<II',data,640,0x401320,relocation)
    with pytest.raises(ValueError,match='relative_count'):build(data)

@pytest.mark.parametrize('bits',[32,64])
def test_valid_optimized_relative_prefix_is_accepted(bits):
    data=fixture(bits,dynamic=True)
    struct.pack_into('<qQ' if bits==64 else '<iI',data,512+3*(16 if bits==64 else 8),0x6ffffff9 if bits==64 else 0x6ffffffa,1)
    r=build(data)
    assert not any(r['initialized'][0x1320:0x1320+bits//8])

def test_present_zero_got_address_is_quarantined_when_mapped():
    data=fixture(dynamic=True)
    struct.pack_into('<Q',data,64+16,0);struct.pack_into('<Q',data,64+56+16,0x1300)
    struct.pack_into('<Q',data,64+112+16,512)
    data[512:640]=bytes(128);struct.pack_into('<qQ',data,512,3,0)
    r=build(data)
    assert r['permissions'][:24]==bytes(24) and r['initialized'][:24]==bytes(24)

@pytest.mark.parametrize('sparse',[False,True])
def test_explicit_analysis_base_preserves_file_bytes_masks_and_link_provenance(sparse):
    data=fixture(dynamic=True);digest=hashlib.sha256(data).hexdigest()
    original=build_elf_memory(bytes(data),target_sha256=digest,space_id=433,sparse=sparse)
    rebased=build_elf_memory(bytes(data),target_sha256=digest,space_id=433,sparse=sparse,analysis_base=0x100000)
    assert original['base']==0x400000 and rebased['base']==0x100000
    assert rebased['image_base_kind']=='analysis_vaddr'
    assert rebased['analysis_addressing']==dict(kind='declared_analysis_base',link_base=0x400000,analysis_base=0x100000,bias=-0x300000)
    assert rebased['unknown_ranges']==original['unknown_ranges']
    for before,after in zip(original.get('regions',[original]),rebased.get('regions',[rebased])):
        assert all(before[k]==after[k] for k in ('bytes','permissions','initialized'))
        assert after['base']==before['base']-0x300000
        for old,new in zip(before['provenance'],after['provenance']):
            assert new['link_address']==old['address'] and new['address']==old['address']-0x300000

@pytest.mark.parametrize('base',[True,-1,(1<<64)-1])
def test_invalid_analysis_base_is_rejected(base):
    data=fixture();digest=hashlib.sha256(data).hexdigest()
    with pytest.raises(ValueError):build_elf_memory(bytes(data),target_sha256=digest,space_id=0,analysis_base=base)
