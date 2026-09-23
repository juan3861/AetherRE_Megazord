"""Content bounded static profile classifier."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import zipfile
@dataclass(frozen=True)
class ProfileDeclaration:
    profile_id:str; formats:tuple[str,...]; address_spaces:tuple[str,...]; backend_names:tuple[str,...]; static_only:bool=True
@dataclass(frozen=True)
class ProfileMatch:
    profile_id:str; confidence:float; reasons:tuple[str,...]; candidates:tuple[str,...]
PROFILE_DECLARATIONS={
"native-pe":ProfileDeclaration("native-pe",("PE32","PE32+"),("pe:rva","pe:file"),("ghidra","rizin","angr","retdec","binaryninja")),
"native-elf":ProfileDeclaration("native-elf",("ELF32","ELF64"),("elf:vaddr","elf:file"),("ghidra","rizin","angr","retdec","binaryninja")),
"dotnet":ProfileDeclaration("dotnet",("CLR assembly",),("dotnet:token","dotnet:il"),("ilspy",)),
"android-apk":ProfileDeclaration("android-apk",("APK","DEX"),("dex:method","dex:offset","resource:path"),("jadx","apktool","ghidra")),
"wasm":ProfileDeclaration("wasm",("WebAssembly",),("wasm:function","wasm:offset"),("wabt","binaryen")),
"macho":ProfileDeclaration("macho",("Mach-O32","Mach-O64","Mach-O fat"),("macho:vmaddr","macho:file"),("rizin","ghidra")),
"jvm":ProfileDeclaration("jvm",("class","JAR"),("jvm:class","jvm:method","jvm:bci"),("cfr",)),
"firmware":ProfileDeclaration("firmware",("raw","Intel HEX"),("firmware:physical","firmware:file"),("rizin","ghidra")),}
def _zip(target:Path)->tuple[str,...]:
    try:
      with zipfile.ZipFile(target) as z:
       infos=z.infolist()
       if len(infos)>10000 or sum(x.file_size for x in infos)>512*1024*1024: return ()
       names={x.filename.replace('\\','/') for x in infos}
       result=[]
       if any(x.startswith('classes') and x.endswith('.dex') for x in names): result.append('android-apk')
       if any(x.endswith('.class') for x in names): result.append('jvm')
       return tuple(result)
    except (zipfile.BadZipFile,OSError): return ()
def _is_dotnet(raw:bytes)->bool:
    if not raw.startswith(b'MZ') or len(raw)<0x40:return False
    off=int.from_bytes(raw[0x3c:0x40],'little')
    return off+24<=len(raw) and raw[off:off+4]==b'PE\0\0' and b'BSJB' in raw[:min(len(raw),1024*1024)]
def detect_static_profiles(target:Path)->tuple[ProfileMatch,...]:
    raw=target.read_bytes()[:1024*1024]; candidates=[]; reasons={}
    if raw.startswith(b'\x7fELF'):candidates.append('native-elf');reasons['native-elf']=('elf_magic',)
    elif raw.startswith(b'MZ'): p='dotnet' if _is_dotnet(raw) else 'native-pe';candidates.append(p);reasons[p]=('pe_com_descriptor' if p=='dotnet' else 'pe_magic',)
    elif raw.startswith(b'\0asm'):candidates.append('wasm');reasons['wasm']=('wasm_magic',)
    elif raw[:4] in (b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\fe'):
      candidates.append('macho'); reasons['macho']=('macho_thin_magic',)
    elif raw[:4] == b'\xca\xfe\xba\xbe':
      # JVM is CAFEBABE + u2 minor + u2 major (45..100). A fat Mach-O starts
      # with CAFEBABE + nfat_arch + architecture records instead.
      jvm_major = int.from_bytes(raw[6:8], 'big') if len(raw) >= 8 else -1
      p = 'jvm' if 45 <= jvm_major <= 100 else 'macho'
      candidates.append(p); reasons[p]=('jvm_class_header' if p=='jvm' else 'macho_fat_magic',)
    elif raw.startswith(b'dex\n'):candidates.append('android-apk');reasons['android-apk']=('dex_magic',)
    elif raw.startswith(b':'):candidates.append('firmware');reasons['firmware']=('intel_hex',)
    elif raw.startswith(b'PK\x03\x04'):
      candidates.extend(_zip(target)); reasons.update({x:('zip_entries',) for x in candidates})
    return tuple(ProfileMatch(x,1.0,reasons[x],tuple(candidates)) for x in candidates)
def select_static_profile(target:Path,requested:str|None=None)->ProfileMatch:
    matches=detect_static_profiles(target)
    if requested:
      if requested=='firmware' and not matches:return ProfileMatch('firmware',0.0,('explicit_raw_profile',),('firmware',))
      if requested not in PROFILE_DECLARATIONS or not any(x.profile_id==requested for x in matches):raise ValueError('requested_profile_mismatch')
      return next(x for x in matches if x.profile_id==requested)
    if not matches:raise ValueError('profile_unknown')
    if len(matches)!=1:raise ValueError('profile_ambiguous')
    return matches[0]