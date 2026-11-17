"""AetherRE Megazord — PE Authenticode, PKCS#7, Rich Header & Security Forensics (GEAR-03).

Pure-static, zero-execution forensic analyzer for Windows PE security artifacts:
- IMAGE_DIRECTORY_ENTRY_SECURITY (WIN_CERTIFICATE + PKCS#7 / CMS SignedData)
- Microsoft Authenticode PE image digest calculation & SpcIndirectDataContent comparison
- X.509 certificate chain inspection (subject, issuer, validity, fingerprints, CVE-2020-0601 explicit curve check)
- PE Rich Header XOR decryption & compiler/linker toolchain provenance
- DllCharacteristics mitigations (ASLR, High-Entropy, DEP/NX, CFG, ForceIntegrity, NoSEH)
- TLS Callback table inspection & post-section overlay profiling
"""

from __future__ import annotations

import hashlib
import math
import struct
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs7

SCHEMA = "re-megazord-authenticode-audit.v1"
MAX_PE_BYTES = 256 * 1024 * 1024

_OID_ALG_MAP = {
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
    "1.2.840.113549.2.5": "md5",
}

_SPC_INDIRECT_DATA_OID = "1.3.6.1.4.1.311.2.1.4"


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / total
            ent -= p * math.log2(p)
    return round(ent, 4)


def _read_asn1_tlv(buf: bytes, offset: int) -> tuple[int, bytes, int]:
    """Read one DER TLV element starting at offset -> (tag, value_bytes, next_offset)."""
    if offset >= len(buf):
        raise ValueError("asn1_eof")
    tag = buf[offset]
    pos = offset + 1
    if (tag & 0x1F) == 0x1F:
        while pos < len(buf) and (buf[pos] & 0x80):
            pos += 1
        pos += 1
    if pos >= len(buf):
        raise ValueError("asn1_len_eof")
    first_len = buf[pos]
    pos += 1
    if first_len & 0x80:
        num_octets = first_len & 0x7F
        if num_octets == 0 or num_octets > 4 or pos + num_octets > len(buf):
            raise ValueError("asn1_indefinite_or_oob_len")
        length = int.from_bytes(buf[pos:pos + num_octets], "big")
        pos += num_octets
    else:
        length = first_len
    if pos + length > len(buf):
        raise ValueError("asn1_value_oob")
    return tag, buf[pos:pos + length], pos + length


def _decode_oid(raw: bytes) -> str:
    if not raw:
        return ""
    first = raw[0]
    parts = [first // 40, first % 40]
    val = 0
    for b in raw[1:]:
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(val)
            val = 0
    return ".".join(str(p) for p in parts)


def _extract_spc_digest_from_pkcs7(der_blob: bytes) -> tuple[str | None, bytes | None]:
    """Walk DER PKCS#7 SignedData to extract SpcIndirectDataContent (alg_name, digest_bytes)."""
    try:
        tag, root_val, _ = _read_asn1_tlv(der_blob, 0)
        if tag != 0x30:
            return None, None
        # ContentInfo: contentType OID + [0] EXPLICIT content (SignedData)
        _, oid_bytes, pos = _read_asn1_tlv(root_val, 0)
        _, content_wrapper, _ = _read_asn1_tlv(root_val, pos)
        _, signed_data, _ = _read_asn1_tlv(content_wrapper, 0)
        # SignedData: version, digestAlgorithms, encapContentInfo
        _, _, pos = _read_asn1_tlv(signed_data, 0)  # version
        _, _, pos = _read_asn1_tlv(signed_data, pos)  # digestAlgorithms
        _, encap_ci, _ = _read_asn1_tlv(signed_data, pos)  # encapContentInfo
        _, e_oid_raw, e_pos = _read_asn1_tlv(encap_ci, 0)
        if _decode_oid(e_oid_raw) != _SPC_INDIRECT_DATA_OID:
            return None, None
        _, e_wrapper, _ = _read_asn1_tlv(encap_ci, e_pos)
        _, spc_seq, _ = _read_asn1_tlv(e_wrapper, 0)
        # SpcIndirectDataContent: data (SpcAttributeTypeAndOptionalValue), messageDigest (DigestInfo)
        _, _, s_pos = _read_asn1_tlv(spc_seq, 0)
        _, digest_info, _ = _read_asn1_tlv(spc_seq, s_pos)
        # DigestInfo: digestAlgorithm (AlgorithmIdentifier), digest (OCTET STRING)
        _, alg_seq, d_pos = _read_asn1_tlv(digest_info, 0)
        _, alg_oid_raw, _ = _read_asn1_tlv(alg_seq, 0)
        alg_name = _OID_ALG_MAP.get(_decode_oid(alg_oid_raw))
        d_tag, digest_bytes, _ = _read_asn1_tlv(digest_info, d_pos)
        if d_tag != 0x04 or not alg_name:
            return None, None
        return alg_name, digest_bytes
    except Exception:
        return None, None


def compute_pe_authenticode_digest(blob: bytes, alg: str = "sha256") -> str | None:
    """Compute Microsoft Authenticode PE image digest without executing the binary."""
    if alg not in ("md5", "sha1", "sha256", "sha384", "sha512"):
        return None
    if len(blob) < 0x40 or blob[:2] != b"MZ":
        return None
    pe_offset = struct.unpack_from("<I", blob, 0x3C)[0]
    if pe_offset < 0x40 or pe_offset + 24 > len(blob) or blob[pe_offset:pe_offset + 4] != b"PE\0\0":
        return None
    file_header = pe_offset + 4
    _, section_count, _, _, _, optional_size, _ = struct.unpack_from("<HHIIIHH", blob, file_header)
    optional = file_header + 20
    if optional + optional_size > len(blob) or optional_size < 68:
        return None
    magic = struct.unpack_from("<H", blob, optional)[0]
    if magic == 0x10B:
        checksum_off = optional + 64
        num_rva_off = optional + 92
        data_dir_off = optional + 96
    elif magic == 0x20B:
        checksum_off = optional + 64
        num_rva_off = optional + 108
        data_dir_off = optional + 112
    else:
        return None
    if num_rva_off + 4 > optional + optional_size:
        return None
    num_rvas = struct.unpack_from("<I", blob, num_rva_off)[0]
    size_of_headers = struct.unpack_from("<I", blob, optional + 60)[0]
    if size_of_headers > len(blob):
        return None

    sec_dir_off = data_dir_off + 8 * 4 if num_rvas > 4 and data_dir_off + 8 * 5 <= optional + optional_size else None
    sec_table_file_off = 0
    sec_table_size = 0
    if sec_dir_off is not None:
        sec_table_file_off, sec_table_size = struct.unpack_from("<II", blob, sec_dir_off)

    h = hashlib.new(alg)
    h.update(blob[0:checksum_off])
    # Skip 4-byte CheckSum
    cursor = checksum_off + 4
    if sec_dir_off is not None:
        h.update(blob[cursor:sec_dir_off])
        cursor = sec_dir_off + 8  # Skip 8-byte Certificate Table directory entry
    if cursor < size_of_headers:
        h.update(blob[cursor:size_of_headers])

    section_table = optional + optional_size
    if section_table + section_count * 40 > len(blob):
        return None
    sections = []
    for idx in range(section_count):
        off = section_table + idx * 40
        _, _, raw_size, raw_ptr = struct.unpack_from("<IIII", blob, off + 8)
        if raw_size > 0:
            sections.append((raw_ptr, raw_size))
    sections.sort(key=lambda x: x[0])

    sum_of_bytes_hashed = size_of_headers
    for raw_ptr, raw_size in sections:
        if raw_ptr + raw_size > len(blob):
            return None
        h.update(blob[raw_ptr:raw_ptr + raw_size])
        sum_of_bytes_hashed = max(sum_of_bytes_hashed, raw_ptr + raw_size)

    # Extra data (overlay) excluding the certificate table
    if len(blob) > sum_of_bytes_hashed:
        if sec_table_size > 0 and sec_table_file_off >= sum_of_bytes_hashed and sec_table_file_off + sec_table_size <= len(blob):
            h.update(blob[sum_of_bytes_hashed:sec_table_file_off])
            tail_start = sec_table_file_off + sec_table_size
            if tail_start < len(blob):
                h.update(blob[tail_start:])
        else:
            h.update(blob[sum_of_bytes_hashed:])

    return h.hexdigest()


def _parse_rich_header(blob: bytes, pe_offset: int) -> dict[str, Any]:
    """Decrypt and parse PE Rich Header between 0x80 and pe_offset."""
    region = blob[0x80:pe_offset]
    rich_idx = region.rfind(b"Rich")
    if rich_idx == -1 or rich_idx + 8 > len(region):
        return {"present": False, "entries": []}
    xor_key = region[rich_idx + 4:rich_idx + 8]
    if len(xor_key) != 4:
        return {"present": False, "entries": []}
    encrypted = region[:rich_idx]
    if len(encrypted) % 4 != 0 or len(encrypted) < 16:
        return {"present": False, "entries": []}
    decrypted = bytes(b ^ xor_key[i % 4] for i, b in enumerate(encrypted))
    dans_idx = decrypted.find(b"DanS")
    if dans_idx == -1 or (len(decrypted) - dans_idx) < 16:
        return {"present": False, "entries": []}
    payload = decrypted[dans_idx + 16:]
    entries = []
    for pos in range(0, len(payload) - 7, 8):
        comp_id, count = struct.unpack_from("<II", payload, pos)
        build_num = comp_id & 0xFFFF
        prod_id = (comp_id >> 16) & 0xFFFF
        entries.append({"prod_id": prod_id, "build_number": build_num, "count": count})
    return {
        "present": True,
        "xor_key": xor_key.hex(),
        "rich_sha256": hashlib.sha256(decrypted[dans_idx:]).hexdigest(),
        "entries": entries,
    }


def _inspect_certificate(cert: x509.Certificate) -> dict[str, Any]:
    pub = cert.public_key()
    key_type = type(pub).__name__
    key_size = getattr(pub, "key_size", None)
    anomalies: list[str] = []
    if isinstance(pub, ec.EllipticCurvePublicKey):
        # Check for CVE-2020-0601 style explicit curve parameters or weak curves
        curve_name = getattr(pub.curve, "name", "")
        if not curve_name or curve_name == "unknown":
            anomalies.append("explicit_or_unknown_ec_curve_cve_2020_0601_risk")
    elif isinstance(pub, rsa.RSAPublicKey) and (key_size or 0) < 2048:
        anomalies.append(f"weak_rsa_key_{key_size}_bits")

    is_self_signed = cert.issuer == cert.subject
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_hex": format(cert.serial_number, "x"),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
        "key_type": key_type,
        "key_bits": key_size,
        "is_self_signed": is_self_signed,
        "anomalies": anomalies,
    }


def audit_pe_authenticode(data: bytes) -> dict[str, Any]:
    """Run full static PE Authenticode, Rich Header, Mitigations & Overlay audit."""
    if not isinstance(data, (bytes, bytearray)):
        return {"schema": SCHEMA, "status": "invalid", "code": "bytes_required"}
    blob = bytes(data)
    if len(blob) > MAX_PE_BYTES:
        return {"schema": SCHEMA, "status": "invalid", "code": "input_too_large"}
    if len(blob) < 0x40 or blob[:2] != b"MZ":
        return {"schema": SCHEMA, "status": "invalid", "code": "not_pe_mz"}

    pe_offset = struct.unpack_from("<I", blob, 0x3C)[0]
    if pe_offset < 0x40 or pe_offset + 24 > len(blob) or blob[pe_offset:pe_offset + 4] != b"PE\0\0":
        return {"schema": SCHEMA, "status": "invalid", "code": "pe_header_invalid"}

    file_header = pe_offset + 4
    machine, section_count, timestamp, _, _, optional_size, characteristics = struct.unpack_from("<HHIIIHH", blob, file_header)
    optional = file_header + 20
    if optional + optional_size > len(blob) or optional_size < 72:
        return {"schema": SCHEMA, "status": "invalid", "code": "optional_header_invalid"}

    magic = struct.unpack_from("<H", blob, optional)[0]
    if magic == 0x10B:
        is_64 = False
        num_rva_off, data_dir_off = optional + 92, optional + 96
    elif magic == 0x20B:
        is_64 = True
        num_rva_off, data_dir_off = optional + 108, optional + 112
    else:
        return {"schema": SCHEMA, "status": "invalid", "code": "unsupported_optional_magic"}

    dll_chars = struct.unpack_from("<H", blob, optional + 70)[0]
    mitigations = {
        "aslr": bool(dll_chars & 0x0040),
        "high_entropy_va": bool(dll_chars & 0x0020),
        "dep_nx": bool(dll_chars & 0x0100),
        "force_integrity": bool(dll_chars & 0x0080),
        "control_flow_guard": bool(dll_chars & 0x4000),
        "no_seh": bool(dll_chars & 0x0400),
        "appcontainer": bool(dll_chars & 0x1000),
    }

    rich = _parse_rich_header(blob, pe_offset)

    num_rvas = struct.unpack_from("<I", blob, num_rva_off)[0] if num_rva_off + 4 <= optional + optional_size else 0
    has_tls = False
    if num_rvas > 9 and data_dir_off + 8 * 10 <= optional + optional_size:
        tls_rva, tls_size = struct.unpack_from("<II", blob, data_dir_off + 8 * 9)
        has_tls = tls_rva > 0 and tls_size > 0

    # Overlay calculation
    section_table = optional + optional_size
    max_raw_end = struct.unpack_from("<I", blob, optional + 60)[0]
    if section_table + section_count * 40 <= len(blob):
        for idx in range(section_count):
            off = section_table + idx * 40
            _, _, raw_size, raw_ptr = struct.unpack_from("<IIII", blob, off + 8)
            if raw_size > 0 and raw_ptr + raw_size <= len(blob):
                max_raw_end = max(max_raw_end, raw_ptr + raw_size)

    sec_file_off = 0
    sec_size = 0
    if num_rvas > 4 and data_dir_off + 8 * 5 <= optional + optional_size:
        sec_file_off, sec_size = struct.unpack_from("<II", blob, data_dir_off + 8 * 4)

    overlay_size = 0
    overlay_entropy = 0.0
    if len(blob) > max_raw_end:
        if sec_size > 0 and sec_file_off >= max_raw_end and sec_file_off + sec_size <= len(blob):
            ov_bytes = blob[max_raw_end:sec_file_off] + blob[sec_file_off + sec_size:]
        else:
            ov_bytes = blob[max_raw_end:]
        overlay_size = len(ov_bytes)
        overlay_entropy = _shannon_entropy(ov_bytes[:1024 * 1024])

    base_report: dict[str, Any] = {
        "schema": SCHEMA,
        "machine": hex(machine),
        "is_64bit": is_64,
        "timestamp": timestamp,
        "mitigations": mitigations,
        "has_tls_directory": has_tls,
        "rich_header": rich,
        "overlay": {"size": overlay_size, "entropy": overlay_entropy},
        "authenticode": {
            "signed": False,
            "digest_algorithm": None,
            "embedded_digest": None,
            "computed_digest": None,
            "digest_match": None,
            "certificates": [],
            "trust_store_verified": False,
        },
    }

    if sec_file_off == 0 or sec_size == 0:
        base_report["status"] = "unsigned"
        return base_report

    if sec_file_off < max_raw_end or sec_file_off + sec_size > len(blob) or sec_size < 8:
        base_report["status"] = "signed_invalid_directory"
        return base_report

    win_len, win_rev, win_type = struct.unpack_from("<IHH", blob, sec_file_off)
    if win_len < 8 or win_len > sec_size or win_type != 0x0002:
        base_report["status"] = "signed_unsupported_cert_type"
        base_report["authenticode"]["win_revision"] = hex(win_rev)
        base_report["authenticode"]["win_cert_type"] = hex(win_type)
        return base_report

    pkcs7_der = blob[sec_file_off + 8:sec_file_off + win_len]
    try:
        certs = pkcs7.load_der_pkcs7_certificates(pkcs7_der)
    except Exception as exc:
        base_report["status"] = "signed_pkcs7_parse_error"
        base_report["authenticode"]["error"] = str(exc)
        return base_report

    alg_name, embedded_digest_bytes = _extract_spc_digest_from_pkcs7(pkcs7_der)
    embedded_hex = embedded_digest_bytes.hex() if embedded_digest_bytes else None
    computed_hex = compute_pe_authenticode_digest(blob, alg_name) if alg_name else None
    digest_match = (embedded_hex == computed_hex) if (embedded_hex and computed_hex) else None

    if digest_match is True:
        status = "signed_valid_digest"
    elif digest_match is False:
        status = "signed_digest_mismatch"
    else:
        status = "signed_digest_unextracted"

    base_report["status"] = status
    base_report["authenticode"] = {
        "signed": True,
        "win_revision": hex(win_rev),
        "win_cert_type": hex(win_type),
        "digest_algorithm": alg_name,
        "embedded_digest": embedded_hex,
        "computed_digest": computed_hex,
        "digest_match": digest_match,
        "certificates": [_inspect_certificate(c) for c in certs],
        "trust_store_verified": False,  # Static offline audit; OS root trust chain not queried
    }
    return base_report


def scan_file_authenticode(target: str | Path) -> dict[str, Any]:
    path = Path(target)
    if not path.is_file():
        raise FileNotFoundError(f"Target file not found: {path}")
    if path.stat().st_size > MAX_PE_BYTES:
        return {"schema": SCHEMA, "status": "invalid", "code": "file_too_large", "target": str(path)}
    report = audit_pe_authenticode(path.read_bytes())
    report["target"] = str(path)
    return report
