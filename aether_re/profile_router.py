"""Content-signature based routing with explicit ambiguity abstention."""
from __future__ import annotations

import math
import struct
from dataclasses import asdict, dataclass
from pathlib import Path

from .evidence_store import EvidenceStore
from .intake import IntakeResult
from .kernel_contracts import EpistemicState

@dataclass(frozen=True)
class ProfileCandidate:
    profile_id: str
    strength: int
    evidence: tuple[str,...]
    def to_dict(self): return asdict(self)

@dataclass(frozen=True)
class ProfileDecision:
    schema: str
    profile_id: str
    pipeline: tuple[str,...]
    candidates: tuple[ProfileCandidate,...]
    epistemic_state: EpistemicState
    limitations: tuple[str,...]
    def to_dict(self):
        return {"schema":self.schema,"profile_id":self.profile_id,"pipeline":list(self.pipeline),"candidates":[item.to_dict() for item in self.candidates],"epistemic_state":self.epistemic_state.value,"limitations":list(self.limitations)}

def _pe(data: bytes) -> bool:
    if len(data)<0x40 or not data.startswith(b"MZ"): return False
    offset=int.from_bytes(data[0x3c:0x40],"little")
    return offset>=0x40 and offset+4<=len(data) and data[offset:offset+4]==b"PE\0\0"

def _entropy(data: bytes) -> float:
    if not data: return 0
    counts=[0]*256
    for byte in data: counts[byte]+=1
    return -sum((c/len(data))*math.log2(c/len(data)) for c in counts if c)

def _collect_candidates(result: IntakeResult, store: EvidenceStore) -> list[ProfileCandidate]:
    root=store.resolve(result.root_artifact); data=root.read_bytes()[:1024*1024]
    candidates=[]
    if _pe(data):
        candidates.append(ProfileCandidate("native-pe",100,("offset:0:MZ","pe-header:valid")))
        # CLR metadata is a bounded corroborating signature after a valid PE.
        if b"BSJB" in data: candidates.append(ProfileCandidate("dotnet",95,(f"offset:{data.index(b'BSJB')}:BSJB","pe-header:valid")))
    if data.startswith(b"\x7fELF") and len(data)>=20:
        candidates.append(ProfileCandidate("native-elf",100,("offset:0:ELF","elf-header:valid")))
    wasm_offset = data.find(b"\0asm\x01\0\0\0")
    if wasm_offset == 0:
        candidates.append(ProfileCandidate("wasm", 100, ("offset:0:wasm-v1",)))
    elif wasm_offset > 0:
        candidates.append(ProfileCandidate("wasm", 90, (f"offset:{wasm_offset}:embedded-wasm",)))
    magics={b"\xfe\xed\xfa\xce":"mach-o-32",b"\xce\xfa\xed\xfe":"mach-o-32-be",b"\xfe\xed\xfa\xcf":"mach-o-64",b"\xcf\xfa\xed\xfe":"mach-o-64-be",b"\xca\xfe\xba\xbe":"mach-o-fat",b"\xbe\xba\xfe\xca":"mach-o-fat"}
    for magic,label in magics.items():
        if data.startswith(magic): candidates.append(ProfileCandidate("mach-o",100,(f"offset:0:{label}",))); break
    names={str(item.get("relative_path","")) for item in result.inventory}
    bare={name.removeprefix("archive/") for name in names}
    if "AndroidManifest.xml" in bare and "classes.dex" in bare: candidates.append(ProfileCandidate("android",95,("member:AndroidManifest.xml","member:classes.dex")))
    if any(name.endswith(".class") for name in bare) and "META-INF/MANIFEST.MF" in bare: candidates.append(ProfileCandidate("jvm",95,("member:META-INF/MANIFEST.MF","member:*.class")))
    if result.source_kind=="archive": candidates.append(ProfileCandidate("archive",90,("container:zip-or-tar",)))
    if result.source_kind=="directory":
        suffixes=(".c",".h",".cpp",".cc",".py",".java",".js",".ts",".rs",".go",".cs")
        source_names=[name for name in names if name.lower().endswith(suffixes)]
        if source_names: candidates.append(ProfileCandidate("source-tree",90,tuple(f"member:{n}" for n in sorted(source_names)[:8])))
    if len(data)>=4096 and _entropy(data[:65536])>7.7: candidates.append(ProfileCandidate("firmware-raw",30,("bounded-entropy:high",)))
    return candidates

def _contains_incompatible_profiles(items: tuple[ProfileCandidate,...]) -> bool:
    ids={item.profile_id for item in items}
    # archive is a container, not incompatibility when an inner declared profile matches.
    return len(ids-{"archive"})>1

def _decision_for(selected: ProfileCandidate, candidates: tuple[ProfileCandidate,...]) -> ProfileDecision:
    pipelines={"native-pe":("native-static",),"native-elf":("native-static",),"dotnet":("dotnet-static",),"android":("android-static",),"wasm":("wasm-static",),"jvm":("jvm-static",),"mach-o":("mach-o-static",),"source-tree":("source-static",),"archive":("archive-static",),"firmware-raw":("opaque-static",)}
    state=EpistemicState.EXACT if selected.strength>=90 else EpistemicState.UNKNOWN
    return ProfileDecision("profile-decision.v1",selected.profile_id,pipelines[selected.profile_id],candidates,state,() if state is EpistemicState.EXACT else ("weak signature only",))

def route_case(result: IntakeResult, store: EvidenceStore) -> ProfileDecision:
    candidates=tuple(sorted(_collect_candidates(result,store),key=lambda item:(-item.strength,item.profile_id)))
    strong=tuple(item for item in candidates if item.strength>=90)
    if len(strong)>1 and _contains_incompatible_profiles(strong): return ProfileDecision("profile-decision.v1","manual-review",(),candidates,EpistemicState.UNKNOWN,("conflicting strong signatures",))
    selected=strong[0] if strong else (candidates[0] if candidates else None)
    if selected is None: return ProfileDecision("profile-decision.v1","opaque-static",("opaque-static",),(),EpistemicState.UNKNOWN,("no certified profile matched",))
    return _decision_for(selected,candidates)
