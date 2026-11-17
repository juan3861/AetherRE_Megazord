"""Pure-Python Android Dalvik DEX & APK Offline Forensics (GEAR-17).

Covers Discovery-100 candidates CAN-070 (jadx), CAN-071 (Apktool), CAN-072 (smali),
and CAN-073 (MobSF) without requiring an external JVM runtime.

Capabilities:
  1. Parses raw Dalvik Executable (.dex) files (versions 035..039) and .apk ZIP containers.
  2. Decodes ULEB128 lengths and string_ids pool.
  3. Reconstructs type_ids, method_ids (ClassName->methodName), and class_defs.
  4. Inventories native JNI libraries (lib/<abi>/*.so) inside APK containers.
  5. Detects high-risk Android reflection, dynamic code loading (DexClassLoader),
     native execution (Runtime.exec, System.loadLibrary), and crypto/telephony APIs.
"""

from __future__ import annotations

import io
import struct
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DEX_MAGIC_PREFIX = b"dex\n"
ENDIAN_CONSTANT = 0x12345678

SENSITIVE_ANDROID_INDICATORS = {
    "dynamic_code_loading": [
        "Ldalvik/system/DexClassLoader;",
        "Ldalvik/system/InMemoryDexClassLoader;",
        "Ldalvik/system/PathClassLoader;",
        "Ldalvik/system/BaseDexClassLoader;",
    ],
    "native_execution": [
        "Ljava/lang/System;->loadLibrary",
        "Ljava/lang/System;->load",
        "Ljava/lang/Runtime;->exec",
        "Ljava/lang/ProcessBuilder;",
    ],
    "reflection": [
        "Ljava/lang/Class;->forName",
        "Ljava/lang/reflect/Method;->invoke",
    ],
    "crypto_and_network": [
        "Ljavax/crypto/Cipher;",
        "Ljavax/crypto/spec/SecretKeySpec;",
        "Ljava/net/HttpURLConnection;",
        "Lokhttp3/OkHttpClient;",
    ],
    "accessibility_and_sms": [
        "Landroid/accessibilityservice/AccessibilityService;",
        "Landroid/telephony/SmsManager;",
        "Landroid/app/admin/DeviceAdminReceiver;",
    ],
}


@dataclass
class DexForensicsReport:
    file_path: str
    container_type: str = "unknown"  # "dex", "apk", "invalid"
    is_valid: bool = False
    dex_version: str = ""
    checksum: int = 0
    sha1_signature: str = ""
    string_count: int = 0
    type_count: int = 0
    method_count: int = 0
    class_count: int = 0
    classes: List[str] = field(default_factory=list)
    methods: List[str] = field(default_factory=list)
    strings_sample: List[str] = field(default_factory=list)
    apk_native_libs: List[str] = field(default_factory=list)
    apk_dex_files: List[str] = field(default_factory=list)
    sensitive_indicators: Dict[str, List[str]] = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _read_uleb128(data: bytes, offset: int) -> Tuple[int, int]:
    """Reads an unsigned LEB128 integer from data at offset, returning (value, new_offset)."""
    result = 0
    shift = 0
    pos = offset
    while pos < len(data):
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            break
        shift += 7
        if shift > 35:
            break
    return result, pos


def parse_dex_bytes(data: bytes, report: Optional[DexForensicsReport] = None) -> DexForensicsReport:
    """Parses a single DEX binary buffer into a DexForensicsReport."""
    if report is None:
        report = DexForensicsReport(file_path="", container_type="dex")

    if len(data) < 112 or not data.startswith(DEX_MAGIC_PREFIX):
        report.error = "Invalid DEX header or buffer smaller than 112 bytes."
        return report

    report.dex_version = data[4:7].decode("ascii", errors="replace")
    report.checksum = struct.unpack_from("<I", data, 8)[0]
    report.sha1_signature = data[12:32].hex()

    header_size = struct.unpack_from("<I", data, 36)[0]
    endian_tag = struct.unpack_from("<I", data, 40)[0]
    if header_size != 0x70 or endian_tag != ENDIAN_CONSTANT:
        report.error = f"Unsupported DEX header_size=0x{header_size:x} or endian_tag=0x{endian_tag:x}"
        return report

    report.is_valid = True

    string_ids_size, string_ids_off = struct.unpack_from("<II", data, 56)
    type_ids_size, type_ids_off = struct.unpack_from("<II", data, 64)
    proto_ids_size, proto_ids_off = struct.unpack_from("<II", data, 72)
    field_ids_size, field_ids_off = struct.unpack_from("<II", data, 80)
    method_ids_size, method_ids_off = struct.unpack_from("<II", data, 88)
    class_defs_size, class_defs_off = struct.unpack_from("<II", data, 96)

    report.string_count = string_ids_size
    report.type_count = type_ids_size
    report.method_count = method_ids_size
    report.class_count = class_defs_size

    # 1. Extract Strings
    strings: List[str] = []
    max_strings = min(string_ids_size, 20000)
    for i in range(max_strings):
        off_pos = string_ids_off + i * 4
        if off_pos + 4 > len(data):
            break
        str_data_off = struct.unpack_from("<I", data, off_pos)[0]
        if str_data_off >= len(data):
            strings.append("")
            continue
        utf16_len, str_start = _read_uleb128(data, str_data_off)
        # Find null terminator
        null_idx = data.find(b"\x00", str_start)
        if null_idx == -1:
            raw_s = data[str_start : str_start + utf16_len]
        else:
            raw_s = data[str_start:null_idx]
        s_val = raw_s.decode("utf-8", errors="replace")
        strings.append(s_val)

    report.strings_sample = [s for s in strings if len(s) >= 4][:200]

    # 2. Extract Types
    types: List[str] = []
    max_types = min(type_ids_size, 10000)
    for i in range(max_types):
        off_pos = type_ids_off + i * 4
        if off_pos + 4 > len(data):
            break
        desc_idx = struct.unpack_from("<I", data, off_pos)[0]
        t_str = strings[desc_idx] if desc_idx < len(strings) else f"type_{desc_idx}"
        types.append(t_str)

    # 3. Extract Methods (class_idx: ushort, proto_idx: ushort, name_idx: uint)
    max_methods = min(method_ids_size, 10000)
    for i in range(max_methods):
        off_pos = method_ids_off + i * 8
        if off_pos + 8 > len(data):
            break
        class_idx, proto_idx, name_idx = struct.unpack_from("<HHI", data, off_pos)
        cls_name = types[class_idx] if class_idx < len(types) else f"cls_{class_idx}"
        m_name = strings[name_idx] if name_idx < len(strings) else f"method_{name_idx}"
        full_sig = f"{cls_name}->{m_name}"
        if len(report.methods) < 500:
            report.methods.append(full_sig)

        # Check sensitive indicators on method signature
        for cat, needles in SENSITIVE_ANDROID_INDICATORS.items():
            for needle in needles:
                if needle in full_sig or needle == cls_name:
                    cat_list = report.sensitive_indicators.setdefault(cat, [])
                    if full_sig not in cat_list:
                        cat_list.append(full_sig)

    # Also check types and strings against indicators
    all_type_set = set(types)
    for cat, needles in SENSITIVE_ANDROID_INDICATORS.items():
        for needle in needles:
            if needle in all_type_set:
                cat_list = report.sensitive_indicators.setdefault(cat, [])
                if needle not in cat_list:
                    cat_list.append(needle)

    # 4. Extract Class Definitions (32 bytes per class_def_item)
    max_classes = min(class_defs_size, 5000)
    for i in range(max_classes):
        off_pos = class_defs_off + i * 32
        if off_pos + 32 > len(data):
            break
        class_idx = struct.unpack_from("<I", data, off_pos)[0]
        cls_name = types[class_idx] if class_idx < len(types) else f"cls_{class_idx}"
        if cls_name not in report.classes:
            report.classes.append(cls_name)

    return report


def analyze_dex_or_apk_bytes(data: bytes, file_path: str = "") -> DexForensicsReport:
    """Analyzes either a raw .dex buffer or an .apk ZIP archive containing classes*.dex."""
    if data.startswith(DEX_MAGIC_PREFIX):
        rep = DexForensicsReport(file_path=file_path, container_type="dex")
        return parse_dex_bytes(data, rep)

    if data.startswith(b"PK\x03\x04"):
        rep = DexForensicsReport(file_path=file_path, container_type="apk")
        try:
            with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
                names = zf.namelist()
                dex_names = sorted([n for n in names if n.endswith(".dex") and "/" not in n])
                so_names = sorted([n for n in names if n.startswith("lib/") and n.endswith(".so")])
                rep.apk_dex_files = dex_names
                rep.apk_native_libs = so_names

                if not dex_names:
                    rep.error = "ZIP archive does not contain root classes*.dex files."
                    return rep

                # Parse primary classes.dex (and additional multidex up to 3)
                for dname in dex_names[:3]:
                    dex_bytes = zf.read(dname)
                    parse_dex_bytes(dex_bytes, rep)
                return rep
        except Exception as exc:
            rep.error = f"APK ZIP parsing error: {exc}"
            return rep

    return DexForensicsReport(
        file_path=file_path,
        container_type="invalid",
        is_valid=False,
        error="Buffer is neither a DEX binary nor a PKZIP/APK archive.",
    )


def scan_file_dex(file_path: str | Path) -> DexForensicsReport:
    """Reads a .dex or .apk file from disk and runs offline Dalvik forensics."""
    p = Path(file_path)
    if not p.is_file():
        return DexForensicsReport(
            file_path=str(p),
            container_type="invalid",
            is_valid=False,
            error=f"File not found: {p}",
        )
    try:
        return analyze_dex_or_apk_bytes(p.read_bytes(), str(p))
    except Exception as exc:
        return DexForensicsReport(
            file_path=str(p),
            container_type="invalid",
            is_valid=False,
            error=f"Read error: {exc}",
        )
