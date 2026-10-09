import hashlib,json
from aether_re.firmware_layout import qualify_firmware_layout

def test_layout_requires_hash_and_nonoverlap(tmp_path):
 blob=tmp_path/'x.bin';blob.write_bytes(b'abcdef')
 layout={'schema':'firmware-layout.v1','artifact_sha256':hashlib.sha256(b'abcdef').hexdigest(),'architecture':'arm','endianness':'little','regions':[{'name':'code','offset':0,'size':4,'kind':'code'},{'name':'data','offset':4,'size':2,'kind':'data'}]}
 dec=tmp_path/'layout.json';dec.write_text(json.dumps(layout))
 assert qualify_firmware_layout(blob,dec)['qualified'] is True
 layout['regions'][1]['offset']=3;dec.write_text(json.dumps(layout))
 assert qualify_firmware_layout(blob,dec)['qualified'] is False
