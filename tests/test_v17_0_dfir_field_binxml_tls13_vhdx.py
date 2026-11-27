"""Pilar 12 (v17.0): Field-Reality DFIR Verification Suite.

Validates real Windows 11 EVTX BinXML, MAM\\x04 Prefetch LZXPRESS Huffman,
NTFS Data Runs / $UsnJrnl / ShimCache, Multi-Chunk E01 / VHDX BAT / ext4 Extents /
BitLocker AES-XTS, real Python ssl TLS 1.3 RFC 8446 HKDF decryption,
PAGEDU64, real MDMP MiniDump delegation, and MSF 7.00 PDB TPI struct offsets.
"""

from __future__ import annotations

import ctypes
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import shutil
import socket
import ssl
import struct
import subprocess
import threading
import uuid
import zlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509.oid import NameOID
import pytest

from aether_re.disk_registry_evtx import (
    parse_evtx_events,
    parse_mft_records,
    parse_prefetch_scca,
    parse_shimcache_appcompat,
    parse_usn_journal_j,
)
from aether_re.forensic_containers import (
    analyze_forensic_image,
    decrypt_bitlocker_xts_sector,
    parse_ewf_e01,
    parse_ext4_superblock_and_root,
    parse_vhdx_image,
)
from aether_re.pcap_forensics import analyze_pcap_file, decrypt_tls_with_ram_secrets
from aether_re.ram_forensics import (
    analyze_physical_ram_file,
    parse_pagedu64_header,
    resolve_pdb_tpi_struct_offsets,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_real_windows11_evtx_binxml(tmp_path: Path) -> None:
    if os.name != "nt" or not shutil.which("wevtutil"):
        pytest.skip("Windows wevtutil required for real Windows 11 Application.evtx export")
    evtx_copy = tmp_path / "real_app.evtx"
    proc = subprocess.run(
        ["wevtutil", "epl", "Application", str(evtx_copy), "/ow:true"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if proc.returncode != 0 or not evtx_copy.exists():
        pytest.skip(f"wevtutil epl failed: {proc.stderr}")

    rep = parse_evtx_events(evtx_copy.read_bytes(), max_events=150)
    assert rep["valid"] is True
    assert rep["binxml_decoded_count"] >= 10
    assert rep["event_count"] >= 10
    with_eid = [e for e in rep["events"] if isinstance(e.get("event_id"), int)]
    assert len(with_eid) >= 5
    with_prov = [e for e in rep["events"] if e.get("provider")]
    assert len(with_prov) >= 5


def test_prefetch_mam04_lzxpress_huffman() -> None:
    if os.name != "nt":
        pytest.skip("ntdll.RtlCompressBuffer requires Windows")

    # Build valid SCCA v30 Prefetch buffer
    scca = bytearray(0x100)
    struct.pack_into("<I", scca, 0, 30)
    scca[4:8] = b"SCCA"
    exe_b = "MAMTEST.EXE\x00".encode("utf-16le")
    scca[16 : 16 + len(exe_b)] = exe_b
    struct.pack_into("<I", scca, 76, 0xDEADBEEF)
    struct.pack_into("<Q", scca, 0x80, 133700000000000000)
    struct.pack_into("<I", scca, 0xD0, 7)

    ntdll = ctypes.windll.ntdll
    fmt = 4  # COMPRESSION_FORMAT_XPRESS_HUFF
    ws_comp = ctypes.c_ulong(0)
    ws_frag = ctypes.c_ulong(0)
    st_ws = ntdll.RtlGetCompressionWorkSpaceSize(fmt, ctypes.byref(ws_comp), ctypes.byref(ws_frag))
    if st_ws != 0:
        pytest.skip(f"RtlGetCompressionWorkSpaceSize(XPRESS_HUFF) unavailable: 0x{st_ws:X}")

    comp_buf = ctypes.create_string_buffer(len(scca) * 2 + 256)
    ws_buf = ctypes.create_string_buffer(max(ws_comp.value, 65536))
    final_sz = ctypes.c_ulong(0)
    st = ntdll.RtlCompressBuffer(
        fmt,
        bytes(scca),
        len(scca),
        comp_buf,
        len(comp_buf),
        4096,
        ctypes.byref(final_sz),
        ws_buf,
    )
    if st != 0:
        pytest.skip(f"RtlCompressBuffer(XPRESS_HUFF) returned 0x{st:X}")

    mam_blob = b"MAM\x04" + struct.pack("<I", len(scca)) + comp_buf.raw[: final_sz.value]
    parsed = parse_prefetch_scca(mam_blob)
    assert parsed["valid"] is True
    assert parsed["compressed_mam"] is True
    assert parsed["executable"] == "MAMTEST.EXE"
    assert parsed["run_count"] == 7


def test_mft_non_resident_data_runs_usn_and_shimcache() -> None:
    rec = bytearray(1024)
    rec[:4] = b"FILE"
    struct.pack_into("<H", rec, 4, 42)
    struct.pack_into("<H", rec, 6, 3)
    struct.pack_into("<H", rec, 0x14, 0x38)
    struct.pack_into("<H", rec, 0x16, 0x01)

    # $FILE_NAME (0x30) at 0x38
    fn_off = 0x38
    name_u16 = "nonres.bin".encode("utf-16le")
    c_len = 66 + len(name_u16)
    attr_fn_len = (24 + c_len + 7) & ~7
    struct.pack_into("<II", rec, fn_off, 0x30, attr_fn_len)
    struct.pack_into("<IH", rec, fn_off + 16, c_len, 24)
    struct.pack_into("<Q", rec, fn_off + 24, 5)
    struct.pack_into("<QQQQ", rec, fn_off + 32, 133700000000000000, 133700000000000000, 133700000000000000, 133700000000000000)
    rec[fn_off + 24 + 64] = len("nonres.bin")
    rec[fn_off + 24 + 65] = 1
    rec[fn_off + 24 + 66 : fn_off + 24 + 66 + len(name_u16)] = name_u16

    # Non-resident $DATA (0x80) runlist: 4 clusters @ LCN 0x20, then +0x10 -> LCN 0x30 (2 clusters)
    d_off = fn_off + attr_fn_len
    runlist = b"\x11\x04\x20\x11\x02\x10\x00"
    attr_d_len = (64 + len(runlist) + 7) & ~7
    struct.pack_into("<II", rec, d_off, 0x80, attr_d_len)
    rec[d_off + 8] = 1  # non_resident
    struct.pack_into("<H", rec, d_off + 32, 64)
    struct.pack_into("<Q", rec, d_off + 48, 24576)
    rec[d_off + 64 : d_off + 64 + len(runlist)] = runlist
    struct.pack_into("<I", rec, d_off + attr_d_len, 0xFFFFFFFF)

    mft_res = parse_mft_records(bytes(rec))
    assert mft_res["record_count"] == 1
    ent = mft_res["entries"][0]
    assert ent["filename"] == "nonres.bin"
    assert ent["logical_size"] == 24576
    assert ent["data_runs"] == [
        {"lcn": 0x20, "cluster_count": 4, "sparse": False},
        {"lcn": 0x30, "cluster_count": 2, "sparse": False},
    ]

    # $UsnJrnl:$J USN_RECORD_V2
    usn_name = "dropper.exe".encode("utf-16le")
    usn_rec = bytearray(64 + len(usn_name))
    struct.pack_into("<IHHQ", usn_rec, 0, len(usn_rec), 2, 0, 42)
    struct.pack_into("<QQI", usn_rec, 24, 1024, 133700000000000000, 0x00000100 | 0x80000000)
    struct.pack_into("<HH", usn_rec, 56, len(usn_name), 64)
    usn_rec[64:] = usn_name
    usn_res = parse_usn_journal_j(bytes(usn_rec))
    assert usn_res["record_count"] == 1
    assert usn_res["records"][0]["filename"] == "dropper.exe"
    assert "FILE_CREATE" in usn_res["records"][0]["reasons"]

    # ShimCache 10ts
    sc_path = r"C:\Temp\aether.exe".encode("utf-16le")
    sc_blob = b"10ts" + struct.pack("<IIH", 0, 2 + len(sc_path) + 8, len(sc_path)) + sc_path + struct.pack("<Q", 133700000000000000)
    sc_res = parse_shimcache_appcompat(sc_blob)
    assert sc_res["entry_count"] == 1
    assert sc_res["entries"][0]["path"] == r"C:\Temp\aether.exe"


def test_forensic_containers_e01_multichunk_vhdx_ext4_xts() -> None:
    # 1. Multi-chunk E01
    c1 = zlib.compress(b"CHUNK_ONE_DATA_")
    c2 = zlib.compress(b"CHUNK_TWO_DATA!")
    sec_pos = 13
    c1_pos = sec_pos + 76
    c2_pos = c1_pos + len(c1)
    tbl_pos = c2_pos + len(c2)
    tbl_size = 100 + 8
    done_pos = tbl_pos + tbl_size

    e01 = bytearray(done_pos + 76)
    e01[:8] = b"EVF\x09\x0d\x0a\xff\x00"
    struct.pack_into("<H", e01, 9, 1)
    # sectors section
    e01[sec_pos : sec_pos + 7] = b"sectors"
    struct.pack_into("<QQI", e01, sec_pos + 16, tbl_pos, tbl_pos - sec_pos, 0)
    e01[c1_pos : c1_pos + len(c1)] = c1
    e01[c2_pos : c2_pos + len(c2)] = c2
    # table section
    e01[tbl_pos : tbl_pos + 5] = b"table"
    struct.pack_into("<QQI", e01, tbl_pos + 16, done_pos, tbl_size, 0)
    struct.pack_into("<I", e01, tbl_pos + 76, 2)
    struct.pack_into("<Q", e01, tbl_pos + 84, 0)
    struct.pack_into("<II", e01, tbl_pos + 100, c1_pos | 0x80000000, c2_pos | 0x80000000)
    # done section
    e01[done_pos : done_pos + 4] = b"done"
    struct.pack_into("<QQI", e01, done_pos + 16, done_pos, 76, 0)

    ewf_res = parse_ewf_e01(bytes(e01))
    assert ewf_res["valid"] is True
    assert ewf_res["chunks_reconstructed"] == 2
    assert ewf_res["decompressed_preview"] == b"CHUNK_ONE_DATA_CHUNK_TWO_DATA!"

    # 2. VHDX with Region Table + BAT
    vhdx = bytearray(0x60000)
    vhdx[:8] = b"vhdxfile"
    vhdx[8:20] = "Aether".encode("utf-16le")
    vhdx[0x30000:0x30004] = b"regi"
    struct.pack_into("<I", vhdx, 0x30008, 1)
    bat_guid = uuid.UUID("2DC27766-F623-4200-9D64-115E9BFD4A08").bytes_le
    vhdx[0x30010:0x30020] = bat_guid
    struct.pack_into("<QII", vhdx, 0x30020, 0x50000, 4096, 1)
    # BAT entry 0: PAYLOAD_BLOCK_FULLY_PRESENT (6) at file_offset 0x100000
    struct.pack_into("<Q", vhdx, 0x50000, (0x1 << 20) | 6)
    vhdx_res = parse_vhdx_image(bytes(vhdx))
    assert vhdx_res["valid"] is True
    assert vhdx_res["bat_entries_present"] == 1
    assert vhdx_res["present_blocks"][0]["file_offset"] == 0x100000

    # 3. ext4 BGDT -> Inode Table -> Extent Tree (0xF30A) -> Dir + File content
    bs = 4096
    ext4 = bytearray(bs * 6)
    struct.pack_into("<II", ext4, 0x400, 64, 6)
    struct.pack_into("<I", ext4, 0x418, 2)  # 4096B blocks
    struct.pack_into("<H", ext4, 0x438, 0xEF53)
    struct.pack_into("<H", ext4, 0x458, 256)
    # BGDT at block 1 (0x1000): inode table at block 2 (0x2000)
    struct.pack_into("<I", ext4, bs + 8, 2)
    # Root inode #2 at 0x2000 + 256
    r_ino = 2 * bs + 256
    struct.pack_into("<HH", ext4, r_ino + 40, 0xF30A, 1)
    struct.pack_into("<IHHI", ext4, r_ino + 52, 0, 1, 0, 3)  # dir block 3
    # File inode #3 at 0x2000 + 512
    f_ino = 2 * bs + 512
    payload = b"AETHER_EXT4_PAYLOAD"
    struct.pack_into("<I", ext4, f_ino + 4, len(payload))
    struct.pack_into("<HH", ext4, f_ino + 40, 0xF30A, 1)
    struct.pack_into("<IHHI", ext4, f_ino + 52, 0, 1, 0, 4)  # file data block 4
    ext4[4 * bs : 4 * bs + len(payload)] = payload
    # Directory entry in block 3
    d_blk = 3 * bs
    fname = b"secret.txt"
    struct.pack_into("<IHBB", ext4, d_blk, 3, bs, len(fname), 1)
    ext4[d_blk + 8 : d_blk + 8 + len(fname)] = fname

    ext4_res = parse_ext4_superblock_and_root(bytes(ext4))
    assert ext4_res["valid"] is True
    assert ext4_res["used_extent_tree"] is True
    assert ext4_res["entries"][0]["name"] == "secret.txt"
    assert ext4_res["entries"][0]["content_preview"] == "AETHER_EXT4_PAYLOAD"

    # 4. BitLocker AES-XTS-256
    xts_key = os.urandom(64)
    plain_sec = b"NTFS    " + os.urandom(504)
    tweak = struct.pack("<QQ", 5, 0)
    ct_sec = Cipher(algorithms.AES(xts_key), modes.XTS(tweak)).encryptor().update(plain_sec)
    assert decrypt_bitlocker_xts_sector(ct_sec, xts_key, 5) == plain_sec


def _make_self_signed_cert(cert_path: Path, key_path: Path) -> None:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(subj)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(priv, hashes.SHA256())
    )
    key_path.write_bytes(
        priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _build_pcap_from_tcp_frames(frames: list[tuple[str, int, str, int, bytes]]) -> bytes:
    out = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    ts = 1732500000
    for idx, (sip, sp, dip, dp, payload) in enumerate(frames):
        eth = b"\x00" * 12 + b"\x08\x00"
        tcp = struct.pack("!HHIIHHHH", sp, dp, 1000 + idx * 100, 1, 0x5018, 65535, 0, 0)
        tot_len = 20 + len(tcp) + len(payload)
        ip = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            tot_len,
            idx + 1,
            0x4000,
            64,
            6,
            0,
            socket.inet_aton(sip),
            socket.inet_aton(dip),
        )
        pkt = eth + ip + tcp + payload
        out += struct.pack("<IIII", ts, idx * 1000, len(pkt), len(pkt)) + pkt
    return bytes(out)


def test_real_live_tls13_handshake_rfc8446_hkdf_decryption(tmp_path: Path) -> None:
    cert_p = tmp_path / "srv.crt"
    key_p = tmp_path / "srv.key"
    keylog_p = tmp_path / "sslkeylog.txt"
    _make_self_signed_cert(cert_p, key_p)

    srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    srv_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    srv_ctx.load_cert_chain(str(cert_p), str(key_p))

    cli_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cli_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    cli_ctx.check_hostname = False
    cli_ctx.verify_mode = ssl.CERT_NONE
    cli_ctx.keylog_filename = str(keylog_p)

    # TCP proxy in localhost capturing genuine TLS 1.3 wire records on both directions
    wire_records: list[tuple[str, bytes]] = []
    srv_sock = socket.socket()
    srv_sock.bind(("127.0.0.1", 0))
    srv_sock.listen(1)
    srv_port = srv_sock.getsockname()[1]

    proxy_sock = socket.socket()
    proxy_sock.bind(("127.0.0.1", 0))
    proxy_sock.listen(1)
    proxy_port = proxy_sock.getsockname()[1]

    def _srv_worker() -> None:
        conn, _ = srv_sock.accept()
        with srv_ctx.wrap_socket(conn, server_side=True) as tls:
            _ = tls.recv(4096)
            tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\nREAL_TLS13_BODY")

    def _proxy_worker() -> None:
        c_conn, _ = proxy_sock.accept()
        s_conn = socket.create_connection(("127.0.0.1", srv_port))

        def _pump(src: socket.socket, dst: socket.socket, tag: str) -> None:
            try:
                while True:
                    chunk = src.recv(16384)
                    if not chunk:
                        break
                    wire_records.append((tag, chunk))
                    dst.sendall(chunk)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        t1 = threading.Thread(target=_pump, args=(c_conn, s_conn, "client"), daemon=True)
        t2 = threading.Thread(target=_pump, args=(s_conn, c_conn, "server"), daemon=True)
        t1.start()
        t2.start()
        t1.join(timeout=5)
        t2.join(timeout=5)
        c_conn.close()
        s_conn.close()

    ts = threading.Thread(target=_srv_worker, daemon=True)
    tp = threading.Thread(target=_proxy_worker, daemon=True)
    ts.start()
    tp.start()

    with socket.create_connection(("127.0.0.1", proxy_port)) as raw_c:
        with cli_ctx.wrap_socket(raw_c, server_hostname="localhost") as tls_c:
            tls_c.sendall(b"GET /aether_tls13_secret HTTP/1.1\r\nHost: localhost\r\n\r\n")
            resp = tls_c.recv(4096)
            assert b"REAL_TLS13_BODY" in resp

    ts.join(timeout=5)
    tp.join(timeout=5)
    srv_sock.close()
    proxy_sock.close()

    # Parse keylog secrets & split wire_records into individual TLS records for PCAP
    secrets: list[dict[str, str]] = []
    for line in keylog_p.read_text(encoding="utf-8").splitlines():
        parts = line.strip().split()
        if len(parts) == 3 and parts[0] in {"CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"}:
            secrets.append({"label": parts[0], "client_random": parts[1], "secret_hex": parts[2]})
    assert len(secrets) >= 2

    pcap_frames: list[tuple[str, int, str, int, bytes]] = []
    for direction, chunk in wire_records:
        pos = 0
        while pos + 5 <= len(chunk):
            rlen = struct.unpack_from("!H", chunk, pos + 3)[0]
            rec = chunk[pos : pos + 5 + rlen]
            if len(rec) < 5 + rlen:
                break
            if direction == "client":
                pcap_frames.append(("10.0.0.2", 55000, "10.0.0.1", 443, rec))
            else:
                pcap_frames.append(("10.0.0.1", 443, "10.0.0.2", 55000, rec))
            pos += 5 + rlen

    pcap_path = tmp_path / "real_tls13.pcap"
    pcap_path.write_bytes(_build_pcap_from_tcp_frames(pcap_frames))
    rep = analyze_pcap_file(str(pcap_path), tls_secrets=secrets)
    plaintexts = [r["plaintext_utf8"] for r in rep.get("decrypted_tls_records", [])]
    joined = "\n".join(plaintexts)
    assert "GET /aether_tls13_secret" in joined
    assert "REAL_TLS13_BODY" in joined


def test_ram_forensics_pagedu64_mdmp_real_and_pdb_tpi() -> None:
    # 1. PAGEDU64 (8KB Windows x64 Crash Dump header)
    pg = bytearray(0x2000)
    pg[:8] = b"PAGEDU64"
    struct.pack_into("<Q", pg, 0x10, 0x1AA000)
    struct.pack_into("<Q", pg, 0x20, 0xFFFFF80012345000)
    struct.pack_into("<I", pg, 0x88, 1)
    struct.pack_into("<QQ", pg, 0x98, 0x10, 0x40)
    pg_res = parse_pagedu64_header(bytes(pg))
    assert pg_res["valid"] is True
    assert pg_res["cr3"] == "0x1aa000"
    assert pg_res["physical_runs"][0]["base_pa"] == 0x10000

    # 2. Real MiniDump delegation on engineering_evidence/live_audited_process.dmp
    real_dmp = REPO_ROOT / "engineering_evidence" / "live_audited_process.dmp"
    if real_dmp.is_file():
        dmp_rep = analyze_physical_ram_file(real_dmp)
        assert dmp_rep["delegated_format"] == "windows_minidump_mdmp"
        assert dmp_rep["modules_count"] > 0

    # 3. Pure-Python MSF 7.00 PDB Stream #2 (TPI) _EPROCESS offsets
    bs = 4096
    # Build TPI Stream (#2): 56-byte header + LF_FIELDLIST (ti=0x1000) + LF_STRUCTURE (ti=0x1001)
    fl_body = (
        struct.pack("<HHIH", 0x150D, 3, 0x75, 0x440) + b"UniqueProcessId\x00"
        + struct.pack("<HHIH", 0x150D, 3, 0x75, 0x448) + b"ActiveProcessLinks\x00"
    )
    fl_rec = struct.pack("<HH", 2 + len(fl_body), 0x1203) + fl_body
    st_body = struct.pack("<HHIIH", 2, 0, 0x1000, 0, 0) + struct.pack("<H", 0xB00) + b"_EPROCESS\x00"
    st_rec = struct.pack("<HH", 2 + len(st_body), 0x1505) + st_body
    tpi_hdr = bytearray(56)
    struct.pack_into("<III", tpi_hdr, 0, 20040203, 56, 0x1000)
    tpi_stream = bytes(tpi_hdr) + fl_rec + st_rec

    # MSF Directory: 3 streams (sizes 0, 0, len(tpi_stream)), stream #2 in block 3
    dir_data = struct.pack("<IIII", 3, 0, 0, len(tpi_stream)) + struct.pack("<I", 3)
    pdb = bytearray(bs * 4)
    pdb[:32] = b"Microsoft C/C++ MSF 7.00\r\n\x1a\x44\x53\x00\x00\x00"
    struct.pack_into("<IIIIII", pdb, 32, bs, 0, 4, len(dir_data), 0, 1)
    struct.pack_into("<I", pdb, bs, 2)  # root map block 1 -> dir block 2
    pdb[2 * bs : 2 * bs + len(dir_data)] = dir_data
    pdb[3 * bs : 3 * bs + len(tpi_stream)] = tpi_stream

    pdb_res = resolve_pdb_tpi_struct_offsets(bytes(pdb), "_EPROCESS")
    assert pdb_res["valid"] is True
    assert pdb_res["fields"] == {
        "UniqueProcessId": "0x440",
        "ActiveProcessLinks": "0x448",
    }
