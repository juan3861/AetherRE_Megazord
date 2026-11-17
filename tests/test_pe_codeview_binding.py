"""CodeView identity cannot bind through an unmapped or ambiguous RVA."""
import struct,uuid

from aether_re.pe_debug import parse_pe_codeview


def pe():
    b=bytearray(2048);b[:2]=b'MZ';struct.pack_into('<I',b,60,128);b[128:132]=b'PE\0\0'
    struct.pack_into('<HHIIIHH',b,132,0x8664,1,0,0,0,240,0)
    opt=152;struct.pack_into('<H',b,opt,0x20b);struct.pack_into('<I',b,opt+56,0x2000);struct.pack_into('<I',b,opt+60,512);struct.pack_into('<I',b,opt+108,16)
    struct.pack_into('<II',b,opt+112+6*8,0x1000,28)
    struct.pack_into('<IIII',b,opt+240+8,1024,0x1000,1024,512)
    payload=b'RSDS'+uuid.UUID('12345678-1234-5678-1234-567812345678').bytes_le+struct.pack('<I',1)+b'owned.pdb\0'
    struct.pack_into('<IIHHIIII',b,512,0,0,0,0,2,len(payload),0x1040,576);b[576:576+len(payload)]=payload
    return b


def test_valid_codeview_uses_section_mapping():
    r=parse_pe_codeview(pe());assert r['status']=='complete' and len(r['records'])==1


def test_raw_offset_outside_headers_is_not_an_rva_mapping():
    b=pe();struct.pack_into('<I',b,152+112+6*8,512)
    r=parse_pe_codeview(b);assert r['status']=='invalid' and not r['records']


def test_debug_directory_outside_size_of_image_cannot_bind():
    b=pe();struct.pack_into('<I',b,152+56,0x1000)
    assert parse_pe_codeview(b)['status']=='invalid'


def test_truncated_directory_or_codeview_payload_cannot_bind():
    for mutation in ('directory','payload','disagree'):
        b=pe()
        if mutation=='directory':struct.pack_into('<I',b,152+112+6*8+4,1050)
        if mutation=='payload':struct.pack_into('<I',b,512+16,4096)
        if mutation=='disagree':struct.pack_into('<I',b,512+20,0x1050)
        assert parse_pe_codeview(b)['status']=='invalid'
