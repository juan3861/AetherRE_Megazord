from pathlib import Path
from aether_re.evidence_store import EvidenceStore
from aether_re.intake import IntakeRequest, prepare_case
from aether_re.kernel_contracts import AuthorizationPolicy, IntakeLimits, EpistemicState
from aether_re.profile_router import route_case
P=AuthorizationPolicy.from_dict({"schema":"authorization-policy.v1","basis":"owner","principal":"test","scope":["static-analysis"]})
def test_content_wasm_not_extension(tmp_path: Path):
    f=tmp_path/'x.txt'; f.write_bytes(b'\0asm\x01\0\0\0')
    r=prepare_case(IntakeRequest(f,tmp_path/'case',P,IntakeLimits()))
    assert route_case(r,EvidenceStore(r.manifest_path.parent)).profile_id=='wasm'
def test_polyglot_abstains(tmp_path: Path):
    f=tmp_path/'x.bin'; body=bytearray(b'MZ'+b'\0'*200); body[0x3c:0x40]=(128).to_bytes(4,'little'); body[128:132]=b'PE\0\0'; body[150:158]=b'\0asm\x01\0\0\0'; f.write_bytes(body)
    r=prepare_case(IntakeRequest(f,tmp_path/'case',P,IntakeLimits()))
    d=route_case(r,EvidenceStore(r.manifest_path.parent)); assert d.profile_id=='manual-review' and d.epistemic_state is EpistemicState.UNKNOWN

def test_router_uses_canonical_android_apk_id(tmp_path: Path):
    import zipfile
    f=tmp_path/'sample.apk'
    with zipfile.ZipFile(f,'w') as archive:
        archive.writestr('AndroidManifest.xml', b'manifest')
        archive.writestr('classes.dex', b'dex\n035\0')
    r=prepare_case(IntakeRequest(f,tmp_path/'case',P,IntakeLimits()))
    assert route_case(r,EvidenceStore(r.manifest_path.parent)).profile_id=='android-apk'

def test_router_uses_canonical_macho_id(tmp_path: Path):
    f=tmp_path/'sample.bin'; f.write_bytes(b'\xcf\xfa\xed\xfe'+b'\0'*64)
    r=prepare_case(IntakeRequest(f,tmp_path/'case',P,IntakeLimits()))
    assert route_case(r,EvidenceStore(r.manifest_path.parent)).profile_id=='macho'

def test_router_uses_canonical_firmware_id_for_weak_raw_match(tmp_path: Path):
    f=tmp_path/'sample.bin'; f.write_bytes(bytes(range(256))*32)
    r=prepare_case(IntakeRequest(f,tmp_path/'case',P,IntakeLimits()))
    assert route_case(r,EvidenceStore(r.manifest_path.parent)).profile_id=='firmware'
