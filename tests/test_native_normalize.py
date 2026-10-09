from aether_re.engines.native_normalize import normalize_native_structure
def test_pe_address_spaces_do_not_alias():
 d=normalize_native_structure('sha256:x','native-pe',{'parse_status':'complete','sections':[{'name':'.text','va':'0x400','raw_offset':'0x400'}],'segments':[],'imports':[],'exports':[],'symbols':[],'relocations':[]},'ev:s')
 assert {x.location.space for x in d.nodes}>={'pe:rva','pe:file'}
from aether_re.engines.native_normalize import normalize_native_structure
from aether_re.ir import canonical_ir_dict


def test_elf_duplicate_symbol_tables_merge_and_preserve_source_records():
    duplicate = {"name": "exported_theta", "value": "0x1123", "rva": "0x1123", "table": 2, "index": 5, "type": 2}
    symtab_copy = {"name": "exported_theta", "value": "0x1123", "rva": "0x1123", "table": 27, "index": 24, "type": 2}
    document = normalize_native_structure(
        "sha256:theta", "native-elf",
        {"parse_status": "complete", "sections": [], "segments": [], "imports": [], "exports": [],
         "symbols": [duplicate, symtab_copy], "relocations": []},
        "sha256:theta#structure",
    )
    symbols = [node for node in document.nodes if node.kind == "symbol" and node.name == "exported_theta"]
    assert len(symbols) == 1
    assert [record["table"] for record in symbols[0].attributes["source_records"]] == [2, 27]
    canonical_ir_dict(document)
