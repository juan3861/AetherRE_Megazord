from aether_re.engines.native_normalize import normalize_native_structure
def test_pe_address_spaces_do_not_alias():
 d=normalize_native_structure('sha256:x','native-pe',{'parse_status':'complete','sections':[{'name':'.text','va':'0x400','raw_offset':'0x400'}],'segments':[],'imports':[],'exports':[],'symbols':[],'relocations':[]},'ev:s')
 assert {x.location.space for x in d.nodes}>={'pe:rva','pe:file'}
