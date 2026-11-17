"""Bounded declared file regions; never a claim of a loaded process image."""
from __future__ import annotations

import hashlib
import re
import struct

MAX_MEMORY_BYTES = 1048576
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_ADDRESS = (1 << 64) - 1


def build_file_memory(data, *, target_sha256, base, space_id, regions):
    """Validate the entire layout before allocation, retaining origin per region.

    Regions are caller declarations. A format-specific verified derivation is
    required before these declarations describe an actual preferred image.
    """
    if type(data) is not bytes or len(data) > MAX_FILE_BYTES:
        raise ValueError('memory_file_bytes_invalid')
    if not isinstance(target_sha256, str) or not re.fullmatch('[0-9a-f]{64}', target_sha256):
        raise ValueError('memory_target_hash_invalid')
    if hashlib.sha256(data).hexdigest() != target_sha256:
        raise ValueError('memory_target_hash_mismatch')
    if type(base) is not int or not 0 <= base <= MAX_ADDRESS:
        raise ValueError('memory_base_invalid')
    if type(space_id) is not int or not 0 <= space_id <= 0xffffffff:
        raise ValueError('memory_space_invalid')
    if type(regions) is not list or not 1 <= len(regions) <= 128:
        raise ValueError('memory_regions_invalid')
    checked=[]
    required={'address','file_offset','file_size','memory_size','permissions','zero_fill'}
    for region in regions:
        if type(region) is not dict or set(region) != required:
            raise ValueError('memory_region_shape')
        address,offset,size,length=(region[k] for k in ('address','file_offset','file_size','memory_size'))
        if any(type(v) is not int for v in (address,offset,size,length)):
            raise ValueError('memory_region_integer')
        if not base <= address <= MAX_ADDRESS or not 1 <= length <= MAX_MEMORY_BYTES:
            raise ValueError('memory_region_range')
        if length-1 > MAX_ADDRESS-address or address-base > MAX_MEMORY_BYTES-length:
            raise ValueError('memory_region_extent')
        if not 0 <= size <= length or not 0 <= offset <= len(data) or size > len(data)-offset:
            raise ValueError('memory_region_file_range')
        permissions=region['permissions']
        if type(permissions) is not str or len(permissions)>3 or any(c not in 'RWX' for c in permissions) or len(set(permissions))!=len(permissions):
            raise ValueError('memory_region_permissions')
        if type(region['zero_fill']) is not bool:
            raise ValueError('memory_region_zero_fill')
        checked.append(dict(region))
    checked.sort(key=lambda r:r['address'])
    end=base
    for region in checked:
        if region['address'] < end:
            raise ValueError('memory_region_overlap')
        end=region['address']+region['memory_size']
    length=end-base
    memory=bytearray(length);initialized=bytearray(length);permissions=bytearray(length)
    provenance=[];zero_fill=False
    for region in checked:
        start=region['address']-base;size=region['file_size'];length=region['memory_size'];offset=region['file_offset']
        payload=data[offset:offset+size]
        memory[start:start+size]=payload
        initialized[start:start+size]=b'\1'*size
        if region['zero_fill']:
            initialized[start+size:start+length]=b'\1'*(length-size)
            zero_fill=zero_fill or length>size
        flags=sum(bit for char,bit in (('R',1),('W',2),('X',4)) if char in region['permissions'])
        permissions[start:start+length]=bytes([flags])*length
        provenance.append({**region,'file_sha256':hashlib.sha256(payload).hexdigest(),
            'tail_origin':'declared_zero_fill' if region['zero_fill'] else 'unknown'})
    return dict(schema='declared-file-memory.v1',target_sha256=target_sha256,base=base,space_id=space_id,
        bytes=bytes(memory),initialized=bytes(initialized),permissions=bytes(permissions),provenance=provenance,
        hypotheses=['caller_declared_regions']+(['declared_zero_fill'] if zero_fill else []),
        process_snapshot_proved=False,binary_equivalence_proved=False)


def build_pe_memory(data, *, target_sha256, space_id):
    """Derive a bounded preferred image; quarantine unobserved loader writes.

    Uses pefile for observed headers, with strict independent range checks.
    Unsupported loader contracts fail closed rather than imply a process map.
    """
    if type(data) is not bytes or not 64 <= len(data) <= MAX_FILE_BYTES:
        raise ValueError('memory_pe_bytes_invalid')
    if hashlib.sha256(data).hexdigest() != target_sha256:
        raise ValueError('memory_target_hash_mismatch')
    def u16(offset):return struct.unpack_from('<H',data,offset)[0]
    def u32(offset):return struct.unpack_from('<I',data,offset)[0]
    if data[:2]!=b'MZ':raise ValueError('memory_pe_dos')
    pe=u32(60)
    if not 64<=pe<=len(data)-24 or data[pe:pe+4]!=b'PE\0\0':raise ValueError('memory_pe_header')
    count=u16(pe+6);optional_size=u16(pe+20);o=pe+24
    if not 1<=count<=96 or optional_size<96 or o+optional_size+count*40>len(data):
        raise ValueError('memory_pe_optional')
    magic=u16(o);machine=u16(pe+4)
    if (magic,machine)==(0x20b,0x8664):bits=64;directory_offset=112;base=struct.unpack_from('<Q',data,o+24)[0]
    elif (magic,machine)==(0x10b,0x14c):bits=32;directory_offset=96;base=u32(o+28)
    else:raise ValueError('memory_pe_machine_unsupported')
    if optional_size<directory_offset:raise ValueError('memory_pe_directory_header')
    ndirs=u32(o+directory_offset-4)
    if ndirs>16 or directory_offset+ndirs*8>optional_size:raise ValueError('memory_pe_directories')
    section_alignment=u32(o+32);file_alignment=u32(o+36)
    if (not 512<=file_alignment<=65536 or file_alignment&(file_alignment-1)
        or section_alignment<4096 or section_alignment&(section_alignment-1) or section_alignment<file_alignment):
        raise ValueError('memory_pe_alignment_unsupported')
    image_size=u32(o+56);headers=u32(o+60)
    if (not 1<=image_size<=MAX_MEMORY_BYTES or image_size%section_alignment
        or not o+optional_size+count*40<=headers<=min(len(data),image_size) or headers%file_alignment
        or base+image_size>1<<bits):raise ValueError('memory_pe_image_extent')
    # Header parser is observational; the checks above/below remain authoritative.
    try:
        import pefile
        observed=pefile.PE(data=data,fast_load=True)
    except Exception as exc:
        raise ValueError('memory_pe_parser_failed') from exc
    try:
        if int(observed.OPTIONAL_HEADER.ImageBase)!=base or len(observed.sections)!=count:
            raise ValueError('memory_pe_parser_disagreement')
    finally:observed.close()
    regions=[dict(address=base,file_offset=0,file_size=headers,memory_size=headers,permissions='R',zero_fill=False)]
    raw_ranges=[(0,headers)]
    for index in range(count):
        s=o+optional_size+40*index
        vsize,va,rawsize,raw=struct.unpack_from('<IIII',data,s+8)
        chars=u32(s+36);span=max(vsize,rawsize)
        if (not span or va%section_alignment or va<headers or va+span>image_size
            or rawsize and (raw<headers or raw%file_alignment or rawsize%file_alignment or raw>len(data) or rawsize>len(data)-raw)):
            raise ValueError('memory_pe_section_range')
        if rawsize:raw_ranges.append((raw,raw+rawsize))
        flags=''.join(c for c,bit in (('R',0x40000000),('W',0x80000000),('X',0x20000000)) if chars&bit)
        regions.append(dict(address=base+va,file_offset=raw if rawsize else 0,file_size=rawsize,memory_size=span,permissions=flags,zero_fill=True))
    raw_ranges.sort()
    if any(a[1]>b[0] for a,b in zip(raw_ranges,raw_ranges[1:])):raise ValueError('memory_pe_raw_overlap')
    directories=[struct.unpack_from('<II',data,o+directory_offset+i*8) for i in range(ndirs)]
    directories+= [(0,0)]*(16-ndirs)
    if any(bool(rva)!=bool(size) for rva,size in directories):raise ValueError('memory_pe_directory_pair')
    for index in (7,8,9,10,11,13,14,15):
        if directories[index]!=(0,0):raise ValueError('memory_pe_loader_contract_unsupported')
    if directories[1]!=(0,0) and directories[12]==(0,0):raise ValueError('memory_pe_imports_require_iat')
    def mapped(rva,size,*,file_backed=False):
        candidates=[]
        if size<=0 or rva<0 or rva+size>image_size:raise ValueError('memory_pe_rva_range')
        for region in regions:
            start=region['address']-base;span=region['file_size'] if file_backed else region['memory_size']
            if start<=rva and rva+size<=start+span:
                candidates.append(region['file_offset']+rva-start)
        if len(candidates)!=1:raise ValueError('memory_pe_rva_mapping')
        return candidates[0]
    # Validate directories before materializing any image. Security index4 uses file offsets.
    for index,(rva,size) in enumerate(directories):
        if not size:continue
        if index==4:
            if rva>len(data) or size>len(data)-rva:raise ValueError('memory_pe_security_range')
        else:mapped(rva,size,file_backed=True)
    unknown=[]
    iat,size=directories[12]
    if size:
        if size%(bits//8):raise ValueError('memory_pe_iat_width')
        unknown.append(dict(rva=iat,size=size,reason='import_address_table'))
    import_rva,import_size=directories[1]
    if import_size:
        if import_size%20 or import_size>20*1025:raise ValueError('memory_pe_import_budget_or_shape')
        import_offset=mapped(import_rva,import_size,file_backed=True)
        terminated=False;thunk_count=0;pointer_size=bits//8
        for pos in range(0,import_size,20):
            lookup,timestamp,chain,name,first=struct.unpack_from('<IIIII',data,import_offset+pos)
            if not any((lookup,timestamp,chain,name,first)):
                terminated=True;break
            if not name or not first or first%pointer_size:raise ValueError('memory_pe_import_descriptor')
            # The descriptor may select another IAT than the directory advertises.
            # Only ranges actually quarantined may receive unobserved loader writes.
            source_thunk=lookup or first
            for index in range(65537):
                thunk_count+=1
                if thunk_count>65536:raise ValueError('memory_pe_import_thunk_budget')
                source_offset=mapped(source_thunk+index*pointer_size,pointer_size,file_backed=True)
                dest=first+index*pointer_size
                if not iat<=dest or dest+pointer_size>iat+size:raise ValueError('memory_pe_import_iat_coverage')
                value=int.from_bytes(data[source_offset:source_offset+pointer_size],'little')
                if value==0:break
            else:raise ValueError('memory_pe_import_thunk_termination')
            mapped(name,1,file_backed=True)
        if not terminated:raise ValueError('memory_pe_import_termination')
    reloc,total=directories[5]
    if total:
        offset=mapped(reloc,total,file_backed=True);cursor=0;entries=0
        while cursor<total:
            if total-cursor<8:raise ValueError('memory_pe_relocation_block')
            page,length=struct.unpack_from('<II',data,offset+cursor)
            if page%4096 or length<8 or length%2 or length>total-cursor:raise ValueError('memory_pe_relocation_block')
            for pos in range(cursor+8,cursor+length,2):
                entry=u16(offset+pos);kind=entry>>12;delta=entry&4095;entries+=1
                if entries>65536:raise ValueError('memory_pe_relocation_budget')
                if kind==0:continue
                if kind!=(10 if bits==64 else 3):raise ValueError('memory_pe_relocation_type_unsupported')
                mapped(page+delta,bits//8)
                unknown.append(dict(rva=page+delta,size=bits//8,reason='base_relocation_target'))
            cursor+=length
    result=build_file_memory(data,target_sha256=target_sha256,base=base,space_id=space_id,regions=regions)
    initialized=bytearray(result['initialized']);permissions=bytearray(result['permissions'])
    for item in unknown:
        start=item['rva'];end=start+item['size']
        initialized[start:end]=bytes(item['size']);permissions[start:end]=bytes(item['size'])
    result.update(schema='preferred-pe-memory.v1',machine=machine,bits=bits,endian='little',image_base_kind='preferred_vaddr',
        declared_image_size=image_size,initialized=bytes(initialized),permissions=bytes(permissions),unknown_ranges=unknown,
        hypotheses=['preferred_static_image_no_process_capture'],relocations_applied=False,imports_resolved=False)
    for region in result['provenance']:
        if region['tail_origin']=='declared_zero_fill':region['tail_origin']='pe_defined_zero_fill'
    return result


def build_elf_memory(data, *, target_sha256, space_id, sparse=False, analysis_base=None):
    """Map ELF32/i386 or ELF64/AMD64 link addresses, without running a loader."""
    if type(sparse) is not bool:raise ValueError('memory_elf_sparse_option')
    if analysis_base is not None and (type(analysis_base) is not int or not 0<=analysis_base<=MAX_ADDRESS):
        raise ValueError('memory_elf_analysis_base')
    if type(data) is not bytes or not 52<=len(data)<=MAX_FILE_BYTES:
        raise ValueError('memory_elf_bytes')
    if hashlib.sha256(data).hexdigest()!=target_sha256:raise ValueError('memory_target_hash_mismatch')
    if data[:4]!=b'\x7fELF' or data[5:7]!=b'\1\1':raise ValueError('memory_elf_encoding_unsupported')
    bits={1:32,2:64}.get(data[4])
    if not bits or len(data)<(64 if bits==64 else 52):raise ValueError('memory_elf_header')
    fmt='<HHIQQQIHHHHHH' if bits==64 else '<HHIIIIIHHHHHH'
    kind,machine,version,entry,phoff,shoff,flags,ehsize,phsize,phcount,shsize,shcount,shstr=struct.unpack_from(fmt,data,16)
    if (kind not in (2,3) or machine!=(62 if bits==64 else 3) or version!=1
        or ehsize!=(64 if bits==64 else 52) or phsize!=(56 if bits==64 else 32)
        or not 1<=phcount<=128 or phoff<ehsize or phoff>len(data) or phsize*phcount>len(data)-phoff):
        raise ValueError('memory_elf_header_layout')
    if shcount and (shcount>4096 or shsize!=(64 if bits==64 else 40) or shoff>len(data) or shcount*shsize>len(data)-shoff):
        raise ValueError('memory_elf_section_budget')
    regions=[];dynamic=[];limit=1<<bits
    for index in range(phcount):
        offset=phoff+index*phsize
        if bits==64:ptype,pflags,raw,address,physical,filesz,memsz,align=struct.unpack_from('<IIQQQQQQ',data,offset)
        else:ptype,raw,address,physical,filesz,memsz,pflags,align=struct.unpack_from('<IIIIIIII',data,offset)
        if ptype==0:continue
        if ptype not in (1,2,3,4,6,7,0x6474e550,0x6474e551,0x6474e552,0x6474e553):
            raise ValueError('memory_elf_segment_type_unsupported')
        if raw>len(data) or filesz>len(data)-raw or address+memsz>limit:
            raise ValueError('memory_elf_segment_range')
        if ptype not in (1,2):continue
        if filesz>memsz or align>1 and (align&(align-1) or address%align!=raw%align):
            raise ValueError('memory_elf_segment_alignment')
        if ptype==2:dynamic.append((address,raw,filesz,memsz));continue
        if not memsz or pflags&~7:raise ValueError('memory_elf_load_flags_or_size')
        permissions=''.join(c for c,bit in (('R',4),('W',2),('X',1)) if pflags&bit)
        regions.append(dict(address=address,file_offset=raw,file_size=filesz,memory_size=memsz,permissions=permissions,zero_fill=True))
    if not regions or len(dynamic)>1:raise ValueError('memory_elf_load_or_dynamic_count')
    base=min(r['address'] for r in regions);end=base
    if sum(r['memory_size'] for r in regions)>MAX_MEMORY_BYTES:raise ValueError('memory_elf_load_budget')
    for region in sorted(regions,key=lambda r:r['address']):
        if region['address']<end or not sparse and region['address']+region['memory_size']-base>MAX_MEMORY_BYTES:
            raise ValueError('memory_elf_load_overlap_or_budget')
        end=region['address']+region['memory_size']
    def mapped(address,size,*,file_backed=False):
        matches=[]
        for region in regions:
            span=region['file_size'] if file_backed else region['memory_size']
            if size>0 and region['address']<=address and address+size<=region['address']+span:
                matches.append(region['file_offset']+address-region['address'])
        if len(matches)!=1:raise ValueError('memory_elf_address_mapping')
        return matches[0]
    unknown=[];width=bits//8;tags={};tables=[]
    if dynamic:
        address,raw,size,memsz=dynamic[0];entry_size=width*2
        if size!=memsz or size%entry_size or not 1<=size//entry_size<=4096 or mapped(address,size,file_backed=True)!=raw:
            raise ValueError('memory_elf_dynamic_range')
        terminated=False
        allowed={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,
            0x6ffffef5,0x6ffffff0,0x6ffffff9,0x6ffffffa,0x6ffffffb,0x6ffffffe,0x6fffffff,0x6ffffffc,0x6ffffffd}
        for pos in range(0,size,entry_size):
            tag,value=struct.unpack_from('<qQ' if bits==64 else '<iI',data,raw+pos)
            if tag==0:terminated=True;break
            if tag not in allowed:raise ValueError('memory_elf_dynamic_tag_unsupported')
            if tag in tags and tag!=1:raise ValueError('memory_elf_dynamic_duplicate')
            tags[tag]=value
            if tag==21:unknown.append(dict(rva=address+pos+width-base,size=width,reason='dynamic_debug_pointer'))
        if not terminated:raise ValueError('memory_elf_dynamic_termination')
        if 3 in tags:
            mapped(tags[3],3*width)
            unknown.append(dict(rva=tags[3]-base,size=3*width,reason='dynamic_plt_got'))
        for addr_tag,size_tag,entry_tag,rela in ((7,8,9,True),(17,18,19,False)):
            if any(t in tags for t in (addr_tag,size_tag,entry_tag)):
                expected=width*(3 if rela else 2)
                if not all(t in tags for t in (addr_tag,size_tag,entry_tag)) or tags[entry_tag]!=expected:
                    raise ValueError('memory_elf_relocation_table_shape')
                tables.append((tags[addr_tag],tags[size_tag],expected,rela))
        if any(t in tags for t in (23,2,20)):
            if not all(t in tags for t in (23,2,20)) or tags[20] not in (7,17):raise ValueError('memory_elf_plt_relocation_shape')
            rela=tags[20]==7;tables.append((tags[23],tags[2],width*(3 if rela else 2),rela))
        for count_tag,addr_tag,size_tag,entry_tag in ((0x6ffffff9,7,8,9),(0x6ffffffa,17,18,19)):
            if count_tag not in tags:continue
            count=tags[count_tag]
            if not all(t in tags for t in (addr_tag,size_tag,entry_tag)) or count>65536 or count>tags[size_tag]//tags[entry_tag]:
                raise ValueError('memory_elf_relative_count_range')
            if count:
                raw=mapped(tags[addr_tag],count*tags[entry_tag],file_backed=True)
                for index in range(count):
                    info=int.from_bytes(data[raw+index*tags[entry_tag]+width:raw+index*tags[entry_tag]+width*2],'little')
                    if info!=8:raise ValueError('memory_elf_relative_count_prefix')
    entries=0
    for address,size,entry_size,rela in tables:
        if size%entry_size or size//entry_size>65536:raise ValueError('memory_elf_relocation_budget')
        if not size:continue
        raw=mapped(address,size,file_backed=True)
        for pos in range(0,size,entry_size):
            target,info=struct.unpack_from('<QQ' if bits==64 else '<II',data,raw+pos)
            reloc=info&((1<<32)-1 if bits==64 else 255);entries+=1
            if entries>65536:raise ValueError('memory_elf_relocation_budget')
            if reloc==0:continue
            if bits==64:
                length={1:8,2:4,6:8,7:8,8:8,10:4,11:4,16:8,17:8,18:8,37:8}.get(reloc)
            else:length=4 if reloc in (1,2,6,7,8,42) else None
            if length is None:raise ValueError('memory_elf_relocation_type_unsupported')
            mapped(target,length)
            unknown.append(dict(rva=target-base,size=length,reason='dynamic_relocation_target'))
    if sparse:
        # Pack only as an internal allocation strategy, never as virtual addresses.
        ordered=sorted(regions,key=lambda r:r['address']);packed=[];cursor=0
        for region in ordered:
            packed.append({**region,'address':cursor});cursor+=region['memory_size']
        packed_result=build_file_memory(data,target_sha256=target_sha256,base=0,space_id=space_id,regions=packed)
        memories=[];cursor=0
        for index,region in enumerate(ordered):
            length=region['memory_size'];origin={**packed_result['provenance'][index],'address':region['address']}
            memories.append(dict(base=region['address'],space_id=space_id,target_sha256=target_sha256,
                bytes=packed_result['bytes'][cursor:cursor+length],initialized=packed_result['initialized'][cursor:cursor+length],
                permissions=packed_result['permissions'][cursor:cursor+length],provenance=[origin]))
            cursor+=length
        result=dict(schema='sparse-linked-elf-memory.v1',base=base,space_id=space_id,target_sha256=target_sha256,
            regions=memories,materialized_bytes=cursor,virtual_extent=end-base,contiguous_runtime_compatible=False,
            process_snapshot_proved=False,binary_equivalence_proved=False)
    else:
        result=build_file_memory(data,target_sha256=target_sha256,base=base,space_id=space_id,regions=regions)
        result['schema']='linked-elf-memory.v1';memories=[result]
    for memory in memories:
        initialized=bytearray(memory['initialized']);permissions=bytearray(memory['permissions'])
        for item in unknown:
            start=base+item['rva']-memory['base'];end_item=start+item['size']
            if 0<=start and end_item<=len(initialized):
                initialized[start:end_item]=bytes(item['size']);permissions[start:end_item]=bytes(item['size'])
        memory.update(initialized=bytes(initialized),permissions=bytes(permissions))
        for region in memory['provenance']:
            if region['tail_origin']=='declared_zero_fill':region['tail_origin']='elf_defined_zero_fill'
    result.update(machine=machine,bits=bits,endian='little',image_base_kind='link_vaddr',elf_type=kind,unknown_ranges=unknown,
        hypotheses=['static_link_addresses_no_process_capture','segment_permissions_before_loader_relro'],relocations_applied=False,imports_resolved=False)
    if analysis_base is not None:
        bias=analysis_base-base
        if analysis_base>=limit or any(r['address']+bias<0 or r['address']+bias+r['memory_size']>limit for r in regions):
            raise ValueError('memory_elf_analysis_extent')
        result.update(base=analysis_base,image_base_kind='analysis_vaddr',
            analysis_addressing=dict(kind='declared_analysis_base',link_base=base,analysis_base=analysis_base,bias=bias))
        if sparse:
            for memory in memories:memory['base']+=bias
        for memory in memories:
            for origin in memory['provenance']:
                origin['link_address']=origin['address'];origin['address']+=bias
        result['hypotheses'].append('caller_declared_analysis_base_not_process_load_address')
    return result
