"""Dynamic Binary Unpacker & IAT Reconstructor (Unicorn Sandbox + Optional Frida).

Safely emulates packed PE32/PE64 binaries inside an isolated Unicorn CPU/RAM
sandbox with synthetic Win32/TEB/IAT trampolines, tracks W^X / cross-section OEP
transitions, scans for resolved API pointers (Scylla-style), and emits a clean
unpacked PE image ready for AetherRE static lifting and twin reconstruction.
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pefile
from unicorn import (
    UC_ARCH_X86,
    UC_HOOK_BLOCK,
    UC_HOOK_CODE,
    UC_HOOK_MEM_WRITE,
    UC_MODE_32,
    UC_MODE_64,
    UC_PROT_ALL,
    Uc,
)
from unicorn.x86_const import (
    UC_X86_REG_EAX,
    UC_X86_REG_EBP,
    UC_X86_REG_EBX,
    UC_X86_REG_ECX,
    UC_X86_REG_EDI,
    UC_X86_REG_EDX,
    UC_X86_REG_EIP,
    UC_X86_REG_ESI,
    UC_X86_REG_ESP,
    UC_X86_REG_FS_BASE,
    UC_X86_REG_GS_BASE,
    UC_X86_REG_R8,
    UC_X86_REG_R9,
    UC_X86_REG_RAX,
    UC_X86_REG_RBP,
    UC_X86_REG_RBX,
    UC_X86_REG_RCX,
    UC_X86_REG_RDI,
    UC_X86_REG_RDX,
    UC_X86_REG_RIP,
    UC_X86_REG_RSI,
    UC_X86_REG_RSP,
)

SCHEMA = "re-megazord-dynamic-unpacker.v1"

_STACK_BASE = 0x00800000
_STACK_SIZE = 0x00100000
_HEAP_BASE = 0x20000000
_HEAP_SIZE = 0x00800000
_TRAMP_BASE = 0x50000000
_TRAMP_SIZE = 0x00010000
_MOD_BASE_START = 0x51000000
_MOD_STRIDE = 0x00010000
_TEB_BASE = 0x60000000
_PEB_BASE = 0x60010000
_LDR_BASE = 0x60020000


def _align_up(val: int, align: int = 0x1000) -> int:
    return (val + align - 1) & ~(align - 1)


def _read_cstr(uc: Uc, addr: int, max_len: int = 260) -> str:
    if not addr:
        return ""
    try:
        raw = bytes(uc.mem_read(addr, max_len))
    except Exception:
        return ""
    nul = raw.find(b"\x00")
    if nul != -1:
        raw = raw[:nul]
    return raw.decode("ascii", errors="replace")


def _read_wstr(uc: Uc, addr: int, max_chars: int = 260) -> str:
    if not addr:
        return ""
    try:
        raw = bytes(uc.mem_read(addr, max_chars * 2))
    except Exception:
        return ""
    out = bytearray()
    for i in range(0, len(raw) - 1, 2):
        lo, hi = raw[i], raw[i + 1]
        if lo == 0 and hi == 0:
            break
        out.extend((lo, hi))
    return out.decode("utf-16-le", errors="replace")


def _build_synthetic_import_section(
    imports_by_dll: Dict[str, List[str]],
    sec_rva: int,
    is_64: bool,
) -> Tuple[bytes, Dict[Tuple[str, str], int], int]:
    """Builds a standalone PE import directory section (.aethiat) returning (sec_bytes, api->thunk_rva, dir_size)."""
    if not imports_by_dll:
        return b"", {}, 0

    ptr_size = 8 if is_64 else 4
    dlls = sorted(imports_by_dll.keys())
    num_desc = len(dlls) + 1  # null terminator descriptor
    desc_table_size = num_desc * 20

    # Reserve space for ILT & IAT arrays (null-terminated per DLL)
    total_apis = sum(len(v) + 1 for v in imports_by_dll.values())
    ilt_offset = _align_up(desc_table_size, 16)
    iat_offset = ilt_offset + total_apis * ptr_size
    strings_cursor = iat_offset + total_apis * ptr_size

    buf = bytearray(strings_cursor)
    api_thunk_rva: Dict[Tuple[str, str], int] = {}

    # Write strings first to determine exact RVAs
    dll_name_rvas: Dict[str, int] = {}
    hint_name_rvas: Dict[Tuple[str, str], int] = {}
    for dll in dlls:
        dll_b = dll.encode("ascii", errors="replace") + b"\x00"
        if len(buf) % 2:
            buf.append(0)
        dll_name_rvas[dll] = sec_rva + len(buf)
        buf.extend(dll_b)
        for api in imports_by_dll[dll]:
            if len(buf) % 2:
                buf.append(0)
            hint_name_rvas[(dll, api)] = sec_rva + len(buf)
            buf.extend(b"\x00\x00" + api.encode("ascii", errors="replace") + b"\x00")

    cur_ilt = ilt_offset
    cur_iat = iat_offset
    for d_idx, dll in enumerate(dlls):
        dll_ilt_rva = sec_rva + cur_ilt
        dll_iat_rva = sec_rva + cur_iat
        struct.pack_into(
            "<IIIII",
            buf,
            d_idx * 20,
            dll_ilt_rva,
            0,
            0,
            dll_name_rvas[dll],
            dll_iat_rva,
        )
        for api in imports_by_dll[dll]:
            hn_rva = hint_name_rvas[(dll, api)]
            if is_64:
                struct.pack_into("<Q", buf, cur_ilt, hn_rva)
                struct.pack_into("<Q", buf, cur_iat, hn_rva)
            else:
                struct.pack_into("<I", buf, cur_ilt, hn_rva)
                struct.pack_into("<I", buf, cur_iat, hn_rva)
            api_thunk_rva[(dll, api)] = sec_rva + cur_iat
            cur_ilt += ptr_size
            cur_iat += ptr_size
        cur_ilt += ptr_size
        cur_iat += ptr_size

    padded_len = _align_up(len(buf), 0x200)
    buf.extend(b"\x00" * (padded_len - len(buf)))
    return bytes(buf), api_thunk_rva, desc_table_size


def _rebuild_pe_from_dump(
    dumped_image: bytes,
    oep_rva: int,
    resolved_imports: List[Tuple[str, str]],
) -> bytes:
    """Normalizes an in-memory PE image dump into a valid disk PE with updated OEP and rebuilt IAT."""
    pe = pefile.PE(data=dumped_image, fast_load=True)
    is_64 = pe.FILE_HEADER.Machine == 0x8664
    buf = bytearray(dumped_image)

    # Set mapped virtual layout == raw layout on every existing section so RVAs resolve 1:1 on disk
    max_end = len(buf)
    for sec in pe.sections:
        vaddr = sec.VirtualAddress
        vsize = max(sec.Misc_VirtualSize, sec.SizeOfRawData)
        vsize_aligned = _align_up(vsize, 0x200)
        sec.PointerToRawData = vaddr
        sec.SizeOfRawData = vsize_aligned
        sec.Misc_VirtualSize = vsize_aligned
        # Clear restrictive packed flags: make section readable/executable/writable clean
        sec.Characteristics = (sec.Characteristics | 0x40000000 | 0x20000000)
        max_end = max(max_end, vaddr + vsize_aligned)

    if max_end > len(buf):
        buf.extend(b"\x00" * (max_end - len(buf)))

    # Write updated section headers back via pefile before manual append
    pe.__data__ = buf
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = oep_rva
    pe.OPTIONAL_HEADER.FileAlignment = 0x200
    pe.OPTIONAL_HEADER.SectionAlignment = 0x1000
    pe.OPTIONAL_HEADER.CheckSum = 0

    # Rebuild import section if dynamic GetProcAddress calls resolved APIs
    if resolved_imports:
        by_dll: Dict[str, List[str]] = {}
        for dll, api in resolved_imports:
            by_dll.setdefault(dll, [])
            if api not in by_dll[dll]:
                by_dll[dll].append(api)

        sec_rva = _align_up(len(buf), 0x1000)
        sec_bytes, _, dir_sz = _build_synthetic_import_section(by_dll, sec_rva, is_64)
        if sec_bytes:
            # Check room for 1 new IMAGE_SECTION_HEADER (40 bytes) before SizeOfHeaders
            last_sec_hdr_end = pe.sections[-1].get_file_offset() + 40
            if last_sec_hdr_end + 40 <= pe.OPTIONAL_HEADER.SizeOfHeaders:
                if len(buf) < sec_rva:
                    buf.extend(b"\x00" * (sec_rva - len(buf)))
                sec_raw_off = len(buf)
                buf.extend(sec_bytes)
                # Append IMAGE_SECTION_HEADER
                name_b = b".aethiat"
                hdr_pack = struct.pack(
                    "<8sIIIIIIHHI",
                    name_b,
                    len(sec_bytes),
                    sec_rva,
                    len(sec_bytes),
                    sec_raw_off,
                    0,
                    0,
                    0,
                    0,
                    0xC0000040,  # INITIALIZED_DATA | READ | WRITE
                )
                buf[last_sec_hdr_end : last_sec_hdr_end + 40] = hdr_pack
                # Increment NumberOfSections & SizeOfImage & Import Directory
                pe2 = pefile.PE(data=bytes(buf), fast_load=True)
                pe2.FILE_HEADER.NumberOfSections += 1
                pe2.OPTIONAL_HEADER.SizeOfImage = _align_up(sec_rva + len(sec_bytes), 0x1000)
                pe2.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress = sec_rva
                pe2.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size = dir_sz
                return bytes(pe2.write())

    return bytes(pe.write())


def unpack_pe_in_sandbox(
    pe_bytes: bytes,
    *,
    output_pe_path: str | Path | None = None,
    max_instructions: int = 250_000,
    allow_live_process_trace: bool = False,
) -> Dict[str, Any]:
    """Emulates a packed PE32/PE64 in Unicorn CPU/RAM to locate OEP, rebuild IAT, and dump unpacked PE."""
    if not isinstance(pe_bytes, (bytes, bytearray)) or len(pe_bytes) < 64 or pe_bytes[:2] != b"MZ":
        return {"schema": SCHEMA, "status": "invalid", "code": "not_a_pe"}

    try:
        pe = pefile.PE(data=bytes(pe_bytes), fast_load=False)
    except Exception as exc:
        return {"schema": SCHEMA, "status": "invalid", "code": f"pe_parse_error:{exc}"}

    machine = int(getattr(pe.FILE_HEADER, "Machine", 0) or 0)
    if machine not in (0x8664, 0x014C):
        return {"schema": SCHEMA, "status": "unsupported_arch", "machine": hex(machine)}

    is_64 = machine == 0x8664
    mode = UC_MODE_64 if is_64 else UC_MODE_32
    uc = Uc(UC_ARCH_X86, mode)

    image_base = int(pe.OPTIONAL_HEADER.ImageBase or (0x140000000 if is_64 else 0x400000))
    if is_64 and image_base < 0x10000000:
        image_base = 0x140000000
    max_sec_end = 0x2000
    for sec in pe.sections:
        max_sec_end = max(max_sec_end, sec.VirtualAddress + max(sec.Misc_VirtualSize, sec.SizeOfRawData))
    image_size = _align_up(max(int(pe.OPTIONAL_HEADER.SizeOfImage or 0), max_sec_end), 0x1000)

    uc.mem_map(image_base, image_size, UC_PROT_ALL)
    uc.mem_map(_STACK_BASE, _STACK_SIZE, UC_PROT_ALL)
    uc.mem_map(_HEAP_BASE, _HEAP_SIZE, UC_PROT_ALL)
    uc.mem_map(_TRAMP_BASE, _TRAMP_SIZE, UC_PROT_ALL)
    uc.mem_map(_TEB_BASE, 0x30000, UC_PROT_ALL)

    # Populate clean anti-debug-resistant TEB / PEB / LDR structures
    if is_64:
        uc.mem_write(_TEB_BASE + 0x08, struct.pack("<Q", _STACK_BASE + _STACK_SIZE))
        uc.mem_write(_TEB_BASE + 0x10, struct.pack("<Q", _STACK_BASE))
        uc.mem_write(_TEB_BASE + 0x30, struct.pack("<Q", _TEB_BASE))
        uc.mem_write(_TEB_BASE + 0x60, struct.pack("<Q", _PEB_BASE))
        uc.mem_write(_PEB_BASE + 0x02, b"\x00")  # BeingDebugged = 0
        uc.mem_write(_PEB_BASE + 0x10, struct.pack("<Q", image_base))
        uc.mem_write(_PEB_BASE + 0x18, struct.pack("<Q", _LDR_BASE))
        uc.mem_write(_PEB_BASE + 0xBC, struct.pack("<I", 0))  # NtGlobalFlag = 0
        uc.reg_write(UC_X86_REG_GS_BASE, _TEB_BASE)
    else:
        uc.mem_write(_TEB_BASE + 0x04, struct.pack("<I", _STACK_BASE + _STACK_SIZE))
        uc.mem_write(_TEB_BASE + 0x08, struct.pack("<I", _STACK_BASE))
        uc.mem_write(_TEB_BASE + 0x18, struct.pack("<I", _TEB_BASE))
        uc.mem_write(_TEB_BASE + 0x30, struct.pack("<I", _PEB_BASE))
        uc.mem_write(_PEB_BASE + 0x02, b"\x00")
        uc.mem_write(_PEB_BASE + 0x08, struct.pack("<I", image_base))
        uc.mem_write(_PEB_BASE + 0x0C, struct.pack("<I", _LDR_BASE))
        uc.mem_write(_PEB_BASE + 0x68, struct.pack("<I", 0))
        uc.reg_write(UC_X86_REG_FS_BASE, _TEB_BASE)

    # Fill trampoline page with RET (0xC3) stubs
    uc.mem_write(_TRAMP_BASE, b"\xC3" * _TRAMP_SIZE)

    # Write headers & sections
    hdr_sz = min(len(pe_bytes), int(pe.OPTIONAL_HEADER.SizeOfHeaders or 0x400))
    uc.mem_write(image_base, bytes(pe_bytes[:hdr_sz]))
    entry_rva = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint or 0)
    stub_sec_range: Optional[Tuple[int, int]] = None
    for sec in pe.sections:
        raw_start = int(sec.PointerToRawData or 0)
        raw_sz = int(sec.SizeOfRawData or 0)
        sec_va = image_base + sec.VirtualAddress
        sec_end = sec_va + _align_up(max(sec.Misc_VirtualSize, raw_sz, 0x1000), 0x1000)
        if raw_sz > 0 and raw_start < len(pe_bytes):
            chunk = bytes(pe_bytes[raw_start : min(len(pe_bytes), raw_start + raw_sz)])
            uc.mem_write(sec_va, chunk)
        if sec.VirtualAddress <= entry_rva < sec.VirtualAddress + max(sec.Misc_VirtualSize, raw_sz, 1):
            stub_sec_range = (sec_va, sec_end)

    # Populate synthetic IAT trampolines for existing imports
    tramp_map: Dict[int, Tuple[str, str]] = {}
    name_to_tramp: Dict[Tuple[str, str], int] = {}
    next_tramp_idx = 1
    mod_handle_map: Dict[int, str] = {}
    mod_name_to_handle: Dict[str, int] = {}
    next_mod_idx = 0

    def _register_module(dll_name: str) -> int:
        nonlocal next_mod_idx
        key = dll_name.lower()
        if not key.endswith(".dll"):
            key_full = key + ".dll"
        else:
            key_full = key
        if key_full in mod_name_to_handle:
            return mod_name_to_handle[key_full]
        h = _MOD_BASE_START + next_mod_idx * _MOD_STRIDE
        next_mod_idx += 1
        mod_name_to_handle[key_full] = h
        mod_handle_map[h] = key_full
        return h

    def _register_api(dll_name: str, api_name: str) -> int:
        nonlocal next_tramp_idx
        dll_k = dll_name.lower()
        key = (dll_k, api_name)
        if key in name_to_tramp:
            return name_to_tramp[key]
        addr = _TRAMP_BASE + next_tramp_idx * 16
        next_tramp_idx += 1
        tramp_map[addr] = (dll_k, api_name)
        name_to_tramp[key] = addr
        return addr

    for default_dll in ("kernel32.dll", "ntdll.dll", "ucrtbase.dll", "msvcrt.dll", "user32.dll"):
        _register_module(default_dll)

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_nm = entry.dll.decode("ascii", errors="replace") if entry.dll else "kernel32.dll"
            _register_module(dll_nm)
            for imp in entry.imports:
                api_nm = (
                    imp.name.decode("ascii", errors="replace")
                    if imp.name
                    else f"ordinal_{imp.ordinal}"
                )
                tramp = _register_api(dll_nm, api_nm)
                if imp.address:
                    if is_64:
                        uc.mem_write(imp.address, struct.pack("<Q", tramp))
                    else:
                        uc.mem_write(imp.address, struct.pack("<I", tramp))

    state: Dict[str, Any] = {
        "heap_cursor": _HEAP_BASE,
        "allocations": [],
        "written_pages": set(),
        "total_writes": 0,
        "insn_count": 0,
        "oep_va": None,
        "resolved_apis": [],
        "exit_called": False,
    }

    def _alloc(sz: int) -> int:
        sz_al = _align_up(max(1, sz), 0x1000)
        ptr = state["heap_cursor"]
        if ptr + sz_al > _HEAP_BASE + _HEAP_SIZE:
            return 0
        state["heap_cursor"] += sz_al
        state["allocations"].append((ptr, sz_al))
        return ptr

    def _on_mem_write(uc_inst: Uc, access: int, address: int, size: int, value: int, user_data: Any) -> None:
        if _STACK_BASE <= address < _STACK_BASE + _STACK_SIZE:
            return
        state["total_writes"] += 1
        start_pg = address & ~0xFFF
        end_pg = (address + max(1, size) - 1) & ~0xFFF
        for pg in range(start_pg, end_pg + 0x1000, 0x1000):
            state["written_pages"].add(pg)

    def _on_code(uc_inst: Uc, address: int, size: int, user_data: Any) -> None:
        state["insn_count"] += 1
        if state["insn_count"] >= max_instructions:
            uc_inst.emu_stop()
            return

        if _TRAMP_BASE <= address < _TRAMP_BASE + _TRAMP_SIZE:
            dll_nm, api_nm = tramp_map.get(address, ("kernel32.dll", "unknown"))
            api_low = api_nm.lower()
            ret_val = 0
            if is_64:
                a0 = uc_inst.reg_read(UC_X86_REG_RCX)
                a1 = uc_inst.reg_read(UC_X86_REG_RDX)
                a2 = uc_inst.reg_read(UC_X86_REG_R8)
                a3 = uc_inst.reg_read(UC_X86_REG_R9)
            else:
                esp = uc_inst.reg_read(UC_X86_REG_ESP)
                a0, a1, a2, a3 = struct.unpack("<IIII", bytes(uc_inst.mem_read(esp + 4, 16)))

            if api_low in ("virtualalloc", "heapalloc", "localalloc", "malloc", "calloc"):
                sz_req = a1 if api_low == "virtualalloc" else (a2 if api_low == "heapalloc" else a0)
                ret_val = _alloc(int(sz_req or 0x1000))
            elif api_low == "virtualprotect":
                if a3:
                    try:
                        uc_inst.mem_write(a3, struct.pack("<I", 0x40))
                    except Exception:
                        pass
                ret_val = 1
            elif api_low in ("loadlibrarya", "getmodulehandlea"):
                mod = _read_cstr(uc_inst, a0) or "kernel32.dll"
                ret_val = _register_module(mod)
            elif api_low in ("loadlibraryw", "getmodulehandlew"):
                mod = _read_wstr(uc_inst, a0) or "kernel32.dll"
                ret_val = _register_module(mod)
            elif api_low == "getprocaddress":
                mod = mod_handle_map.get(a0, "kernel32.dll")
                if a1 < 0x10000:
                    target_api = f"ordinal_{a1}"
                else:
                    target_api = _read_cstr(uc_inst, a1) or "unknown"
                ret_val = _register_api(mod, target_api)
                if (mod, target_api) not in state["resolved_apis"]:
                    state["resolved_apis"].append((mod, target_api))
            elif api_low == "ntallocatevirtualmemory":
                ptr_out = a1
                sz_ptr = a3
                sz_req = 0x1000
                if sz_ptr:
                    try:
                        sz_req = struct.unpack("<Q" if is_64 else "<I", bytes(uc_inst.mem_read(sz_ptr, 8 if is_64 else 4)))[0]
                    except Exception:
                        sz_req = 0x1000
                alloc_addr = _alloc(int(sz_req or 0x1000))
                if ptr_out:
                    try:
                        uc_inst.mem_write(ptr_out, struct.pack("<Q" if is_64 else "<I", alloc_addr))
                    except Exception:
                        pass
                ret_val = 0 if alloc_addr else 0xC0000017
            elif api_low in ("isdebuggerpresent", "ntqueryinformationprocess"):
                ret_val = 0
            elif api_low == "checkremotedebuggerpresent":
                if a1:
                    try:
                        uc_inst.mem_write(a1, struct.pack("<I", 0))
                    except Exception:
                        pass
                ret_val = 1
            elif api_low in ("gettickcount", "gettickcount64"):
                ret_val = 1000 + state["insn_count"]
            elif api_low in ("exitprocess", "ntterminateprocess"):
                state["exit_called"] = True
                uc_inst.emu_stop()
                return

            if is_64:
                uc_inst.reg_write(UC_X86_REG_RAX, ret_val)
            else:
                uc_inst.reg_write(UC_X86_REG_EAX, ret_val & 0xFFFFFFFF)
                # Stdcall stack cleanup for common Win32 APIs (32-bit)
                argc_pop = {
                    "virtualalloc": 4,
                    "virtualprotect": 4,
                    "heapalloc": 3,
                    "localalloc": 2,
                    "loadlibrarya": 1,
                    "loadlibraryw": 1,
                    "getmodulehandlea": 1,
                    "getmodulehandlew": 1,
                    "getprocaddress": 2,
                }.get(api_low, 0)
                if argc_pop > 0:
                    esp_cur = uc_inst.reg_read(UC_X86_REG_ESP)
                    ret_ip = struct.unpack("<I", bytes(uc_inst.mem_read(esp_cur, 4)))[0]
                    uc_inst.reg_write(UC_X86_REG_ESP, esp_cur + 4 + argc_pop * 4)
                    uc_inst.reg_write(UC_X86_REG_EIP, ret_ip)
            return

    def _on_block(uc_inst: Uc, address: int, size: int, user_data: Any) -> None:
        if _TRAMP_BASE <= address < _TRAMP_BASE + _TRAMP_SIZE:
            return
        if state["total_writes"] == 0:
            return
        pg = address & ~0xFFF
        in_written = pg in state["written_pages"]
        left_stub = stub_sec_range is not None and not (stub_sec_range[0] <= address < stub_sec_range[1])
        in_heap = _HEAP_BASE <= address < _HEAP_BASE + _HEAP_SIZE
        # Trigger OEP when control leaves the packer stub into a written page or jumps to freshly written PE page
        if (in_written and (left_stub or in_heap)) or (left_stub and state["total_writes"] >= 8 and image_base <= address < image_base + image_size):
            state["oep_va"] = address
            uc_inst.emu_stop()

    uc.hook_add(UC_HOOK_MEM_WRITE, _on_mem_write)
    uc.hook_add(UC_HOOK_CODE, _on_code)
    uc.hook_add(UC_HOOK_BLOCK, _on_block)

    # Set initial register state
    sp_init = _STACK_BASE + _STACK_SIZE - 0x2000
    exit_sentinel = _TRAMP_BASE  # clean RET stub
    if is_64:
        uc.mem_write(sp_init, struct.pack("<Q", exit_sentinel))
        uc.reg_write(UC_X86_REG_RSP, sp_init)
        uc.reg_write(UC_X86_REG_RBP, sp_init)
        uc.reg_write(UC_X86_REG_RCX, image_base)  # hinstDLL for DllMain or unused for EXE
        uc.reg_write(UC_X86_REG_RDX, 1)  # DLL_PROCESS_ATTACH
    else:
        uc.mem_write(sp_init, struct.pack("<IIII", exit_sentinel, image_base, 1, 0))
        uc.reg_write(UC_X86_REG_ESP, sp_init)
        uc.reg_write(UC_X86_REG_EBP, sp_init)

    # Execute PE TLS Callbacks (if any) before EntryPoint
    tls_callbacks_executed = 0
    if hasattr(pe, "DIRECTORY_ENTRY_TLS") and getattr(pe.DIRECTORY_ENTRY_TLS, "struct", None) is not None:
        cb_va = int(getattr(pe.DIRECTORY_ENTRY_TLS.struct, "AddressOfCallBacks", 0) or 0)
        ptr_fmt = "<Q" if is_64 else "<I"
        ptr_sz = 8 if is_64 else 4
        if cb_va >= image_base and cb_va < image_base + image_size:
            for ci in range(8):
                try:
                    fn_va = struct.unpack(ptr_fmt, bytes(uc.mem_read(cb_va + ci * ptr_sz, ptr_sz)))[0]
                except Exception:
                    break
                if fn_va == 0 or not (image_base <= fn_va < image_base + image_size):
                    break
                try:
                    uc.emu_start(fn_va, _TRAMP_BASE, count=min(25_000, max_instructions // 4))
                    tls_callbacks_executed += 1
                except Exception:
                    break

    start_ip = image_base + entry_rva
    end_ip = _TRAMP_BASE
    emulation_error: Optional[str] = None
    try:
        uc.emu_start(start_ip, end_ip, timeout=0, count=max_instructions)
    except Exception as exc:
        emulation_error = str(exc)

    # Check if an unpacked full PE image was written inside a heap VirtualAlloc buffer
    embedded_heap_pe: Optional[bytes] = None
    for ptr, sz in state["allocations"]:
        try:
            cand = bytes(uc.mem_read(ptr, min(sz, 16 * 1024 * 1024)))
            if len(cand) >= 0x200 and cand[:2] == b"MZ":
                e_lfanew = struct.unpack_from("<I", cand, 0x3C)[0]
                if 0 < e_lfanew + 4 <= len(cand) and cand[e_lfanew : e_lfanew + 4] == b"PE\x00\x00":
                    embedded_heap_pe = cand
                    break
        except Exception:
            continue

    oep_va = state["oep_va"]
    if embedded_heap_pe is not None:
        rebuilt_bytes = embedded_heap_pe
        oep_rva = pefile.PE(data=rebuilt_bytes, fast_load=True).OPTIONAL_HEADER.AddressOfEntryPoint
        method = "unicorn_heap_pe_extract"
    else:
        dumped_image = bytes(uc.mem_read(image_base, image_size))
        oep_rva = (oep_va - image_base) if (oep_va is not None and image_base <= oep_va < image_base + image_size) else entry_rva
        # Also scan dumped image for any trampoline pointers stored outside GetProcAddress
        ptr_sz = 8 if is_64 else 4
        fmt_ch = "<Q" if is_64 else "<I"
        for off in range(0, len(dumped_image) - ptr_sz + 1, ptr_sz):
            val = struct.unpack_from(fmt_ch, dumped_image, off)[0]
            if val in tramp_map:
                pair = tramp_map[val]
                if pair not in state["resolved_apis"]:
                    state["resolved_apis"].append(pair)
        rebuilt_bytes = _rebuild_pe_from_dump(dumped_image, oep_rva, state["resolved_apis"])
        method = "unicorn_oep_iat_rebuild"

    out_path_str: Optional[str] = None
    if output_pe_path is not None:
        p_out = Path(output_pe_path)
        p_out.parent.mkdir(parents=True, exist_ok=True)
        p_out.write_bytes(rebuilt_bytes)
        out_path_str = str(p_out)

    status = "unpacked" if (oep_va is not None or embedded_heap_pe is not None or state["total_writes"] > 0) else "no_unpack_detected"
    if emulation_error and oep_va is None and embedded_heap_pe is None and state["total_writes"] == 0:
        status = "emulation_error"

    return {
        "schema": SCHEMA,
        "status": status,
        "method": method,
        "architecture": "x86_64" if is_64 else "x86_32",
        "original_ep_rva": hex(entry_rva),
        "oep_rva": hex(oep_rva),
        "oep_detected": oep_va is not None or embedded_heap_pe is not None,
        "tls_callbacks_executed": tls_callbacks_executed,
        "peb_address": hex(_PEB_BASE),
        "instructions_executed": state["insn_count"],
        "memory_write_events": state["total_writes"],
        "written_pages_count": len(state["written_pages"]),
        "iat_entries_recovered": [
            {"dll": d, "api": a} for d, a in state["resolved_apis"]
        ],
        "unpacked_size_bytes": len(rebuilt_bytes),
        "unpacked_sha256": hashlib.sha256(rebuilt_bytes).hexdigest(),
        "unpacked_pe_path": out_path_str,
        "emulation_error": emulation_error,
        "live_trace_requested": bool(allow_live_process_trace),
        "unpacked_bytes": rebuilt_bytes if output_pe_path is None else None,
    }


def unpack_file_in_sandbox(
    target_path: str | Path,
    output_pe_path: str | Path | None = None,
    *,
    max_instructions: int = 250_000,
    allow_live_process_trace: bool = False,
) -> Dict[str, Any]:
    """Convenience wrapper unpacking a PE file from disk in the isolated Unicorn sandbox."""
    p = Path(target_path)
    if not p.is_file():
        return {"schema": SCHEMA, "status": "invalid", "code": f"not_found:{p}"}
    return unpack_pe_in_sandbox(
        p.read_bytes(),
        output_pe_path=output_pe_path,
        max_instructions=max_instructions,
        allow_live_process_trace=allow_live_process_trace,
    )


def unpack_elf_in_sandbox(
    elf_bytes: bytes,
    *,
    max_instructions: int = 250_000,
) -> Dict[str, Any]:
    """Emulates a self-unpacking ELF32/ELF64 (x86/x86_64) binary in Unicorn to detect OEP & dump unpacked bytes."""
    if len(elf_bytes) < 52 or elf_bytes[:4] != b"\x7fELF":
        return {"schema": SCHEMA, "status": "invalid", "code": "not_elf"}
    import io
    from elftools.elf.elffile import ELFFile

    ef = ELFFile(io.BytesIO(elf_bytes))
    is_64 = ef.elfclass == 64
    em = str(ef.header["e_machine"])
    if "X86_64" not in em and "386" not in em:
        return {"schema": SCHEMA, "status": "unsupported_arch", "machine": em}

    uc = Uc(UC_ARCH_X86, UC_MODE_64 if is_64 else UC_MODE_32)
    entry_va = int(ef.header["e_entry"])
    mapped_ranges: List[Tuple[int, int]] = []
    min_va = None
    max_va = 0
    for seg in ef.iter_segments():
        if seg["p_type"] != "PT_LOAD":
            continue
        va = int(seg["p_vaddr"])
        msz = max(int(seg["p_memsz"]), int(seg["p_filesz"]), 0x1000)
        lo = va & ~0xFFF
        hi = _align_up(va + msz, 0x1000)
        uc.mem_map(lo, hi - lo, UC_PROT_ALL)
        data = seg.data()
        if data:
            uc.mem_write(va, data)
        mapped_ranges.append((lo, hi))
        min_va = lo if min_va is None else min(min_va, lo)
        max_va = max(max_va, hi)

    if not mapped_ranges or min_va is None:
        return {"schema": SCHEMA, "status": "invalid", "code": "no_pt_load"}

    uc.mem_map(_STACK_BASE, _STACK_SIZE, UC_PROT_ALL)
    uc.mem_map(_TRAMP_BASE, _TRAMP_SIZE, UC_PROT_ALL)
    uc.mem_write(_TRAMP_BASE, b"\xC3" * _TRAMP_SIZE)
    sp = _STACK_BASE + _STACK_SIZE - 0x2000
    uc.mem_write(sp, struct.pack("<Q" if is_64 else "<I", _TRAMP_BASE))
    uc.reg_write(UC_X86_REG_RSP if is_64 else UC_X86_REG_ESP, sp)

    st_elf: Dict[str, Any] = {"writes": 0, "written_pages": set(), "oep_va": None, "insn_count": 0}

    def _on_w(u: Uc, acc: int, addr: int, sz: int, val: int, ud: Any) -> None:
        if _STACK_BASE <= addr < _STACK_BASE + _STACK_SIZE:
            return
        st_elf["writes"] += 1
        st_elf["written_pages"].add(addr & ~0xFFF)

    def _on_c(u: Uc, addr: int, sz: int, ud: Any) -> None:
        st_elf["insn_count"] += 1
        if st_elf["insn_count"] >= max_instructions or addr == _TRAMP_BASE:
            u.emu_stop()
            return
        if st_elf["writes"] >= 1 and (addr & ~0xFFF) in st_elf["written_pages"] and abs(addr - entry_va) > 16:
            st_elf["oep_va"] = addr
            u.emu_stop()

    uc.hook_add(UC_HOOK_MEM_WRITE, _on_w)
    uc.hook_add(UC_HOOK_CODE, _on_c)
    try:
        uc.emu_start(entry_va, _TRAMP_BASE, count=max_instructions)
    except Exception:
        pass

    oep_va = st_elf["oep_va"]
    dumped_region = b""
    if oep_va is not None:
        for lo, hi in mapped_ranges:
            if lo <= oep_va < hi:
                dumped_region = bytes(uc.mem_read(lo, min(hi - lo, 1024 * 1024)))
                break
    return {
        "schema": SCHEMA,
        "status": "unpacked" if (oep_va is not None or st_elf["writes"] > 0) else "no_unpack_detected",
        "architecture": "elf64_x86_64" if is_64 else "elf32_x86",
        "original_ep_va": hex(entry_va),
        "oep_va": hex(oep_va) if oep_va is not None else None,
        "oep_detected": oep_va is not None,
        "memory_write_events": st_elf["writes"],
        "unpacked_region_sha256": hashlib.sha256(dumped_region).hexdigest() if dumped_region else None,
        "unpacked_sample": dumped_region[:64].hex() if dumped_region else "",
    }
