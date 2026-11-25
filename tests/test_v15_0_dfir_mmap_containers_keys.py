from __future__ import annotations

import mmap
from pathlib import Path
import socket
import struct
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from aether_re.forensic_containers import (
    analyze_forensic_image,
    decrypt_bitlocker_sector_with_fvek,
)
from aether_re.pcap_forensics import analyze_pcap_file
from aether_re.ram_forensics import analyze_physical_ram_file


def _wrap_tcp_ipv4(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    eth = b"\xaa\xbb\xcc\xdd\xee\xff\x11\x22\x33\x44\x55\x66\x08\x00"
    tcp = struct.pack("!HHIIHHHH", sport, dport, 1, 0, (5 << 12) | 0x18, 65535, 0, 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return eth + ip + tcp


def test_v150_zero_copy_mmap_ram_kernel_rsds_and_cross_layer_keys(tmp_path: Path) -> None:
    client_random = bytes(range(1, 33))
    tls_key = bytes(range(0xA0, 0xC0))  # 32B AES-256 key
    fvek_key = bytes(range(0x10, 0x30))

    ram = bytearray(0x8000)
    # 1. RSDS PDB GUID record for ntkrnlmp.pdb
    rsds = b"RSDS" + b"\x11\x22\x33\x44" * 4 + struct.pack("<I", 2) + b"ntkrnlmp.pdb\x00"
    ram[0x1000 : 0x1000 + len(rsds)] = rsds
    # 2. SSLKEYLOGFILE line in RAM
    keylog = f"CLIENT_RANDOM {client_random.hex()} {tls_key.hex()}\n".encode("ascii")
    ram[0x2000 : 0x2000 + len(keylog)] = keylog
    # 3. BitLocker FVEK pool block
    ram[0x3000:0x3008] = b"FVEK\x00\x00\x00\x00"
    ram[0x3008:0x3028] = fvek_key

    ram_path = tmp_path / "live_ram.raw"
    ram_path.write_bytes(bytes(ram))

    ram_rep = analyze_physical_ram_file(ram_path)
    assert ram_rep["zero_copy_mmap"] is True
    assert ram_rep["kernel_profile"]["os"] == "windows"
    assert "ntkrnlmp.pdb" in ram_rep["kernel_profile"]["pdb"]
    assert ram_rep["extracted_keys"]["tls_secrets_count"] == 1
    assert ram_rep["extracted_keys"]["fvek_count"] == 1

    # Encrypt BitLocker sector & verify decryption with RAM-extracted FVEK
    ram_fvek = bytes.fromhex(ram_rep["extracted_keys"]["fvek_candidates"][0]["fvek_hex"])
    plain_sec = b"NTFS_BOOT_SECTOR" * 32
    iv = Cipher(algorithms.AES(ram_fvek), modes.ECB()).encryptor()
    iv_val = iv.update(struct.pack("<Q", 512) + b"\x00" * 8) + iv.finalize()
    enc = Cipher(algorithms.AES(ram_fvek), modes.CBC(iv_val)).encryptor()
    cipher_sec = enc.update(plain_sec) + enc.finalize()
    assert decrypt_bitlocker_sector_with_fvek(cipher_sec, ram_fvek, 512) == plain_sec

    # Build PCAP with TLS ClientHello + AES-GCM encrypted ApplicationData (0x17)
    ch = bytearray(struct.pack("!H", 0x0303) + client_random + b"\x00" + struct.pack("!HHH", 2, 0x1301, 0)[:4] + b"\x01\x00")
    hs = struct.pack("!BBH", 1, 0, len(ch)) + ch
    tls_ch = struct.pack("!BHH", 0x16, 0x0301, len(hs)) + hs

    nonce = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c"
    ct = AESGCM(tls_key).encrypt(nonce, b'GET /c2 HTTP/1.1\r\n{"c2_cmd":"exfil_mft"}\r\n', None)
    app_rec = struct.pack("!BHH", 0x17, 0x0303, len(nonce) + len(ct)) + nonce + ct

    pcap_buf = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for i, pl in enumerate((tls_ch, app_rec)):
        fr = _wrap_tcp_ipv4("10.0.0.5", "198.51.100.20", 50000, 443, pl)
        pcap_buf += struct.pack("<IIII", 1730000500 + i, 0, len(fr), len(fr)) + fr
    pcap_path = tmp_path / "encrypted.pcap"
    pcap_path.write_bytes(bytes(pcap_buf))

    pcap_rep = analyze_pcap_file(str(pcap_path), tls_secrets=ram_rep["extracted_keys"]["tls_secrets"])
    assert pcap_rep["zero_copy_mmap"] is True
    assert len(pcap_rep["decrypted_tls_records"]) == 1
    assert "exfil_mft" in pcap_rep["decrypted_tls_records"][0]["plaintext_utf8"]


def test_v150_forensic_containers_e01_gpt_ext4_apfs_bitlocker(tmp_path: Path) -> None:
    # 1. E01 EWF image with zlib compressed sector
    e01 = bytearray(256)
    e01[0:8] = b"EVF\x09\x0d\x0a\xff\x00"
    struct.pack_into("<H", e01, 9, 1)
    comp_chunk = zlib.compress(b"E01_REAL_SECTOR_PAYLOAD" + b"\x00" * 500)
    sec1_off = 13
    sec1_next = 13 + 76 + len(comp_chunk)
    e01[sec1_off : sec1_off + 7] = b"sectors"
    struct.pack_into("<QQI", e01, sec1_off + 16, sec1_next, 76 + len(comp_chunk), 0)
    e01[sec1_off + 76 : sec1_next] = comp_chunk
    e01[sec1_next : sec1_next + 4] = b"done"
    p_e01 = tmp_path / "disk.E01"
    p_e01.write_bytes(bytes(e01))
    rep_e01 = analyze_forensic_image(p_e01)
    assert rep_e01["format"] == "ewf_e01" and rep_e01["ewf"]["decompressed_bytes_count"] > 500

    # 2. GPT + protective MBR disk
    gpt = bytearray(4096)
    gpt[446 + 4] = 0xEE
    struct.pack_into("<II", gpt, 446 + 8, 1, 2000)
    gpt[510:512] = b"\x55\xaa"
    gpt[512:520] = b"EFI PART"
    struct.pack_into("<Q", gpt, 512 + 72, 2)
    struct.pack_into("<II", gpt, 512 + 80, 2, 128)
    ent0 = 2 * 512
    gpt[ent0 : ent0 + 16] = b"\x28\x73\x2a\xc1\x1f\xf8\xd2\x11\xba\x4b\x00\xa0\xc9\x3e\xc9\x3b"
    struct.pack_into("<QQQ", gpt, ent0 + 32, 34, 2048, 0)
    pname = "Linux RootFS".encode("utf-16le")
    gpt[ent0 + 56 : ent0 + 56 + len(pname)] = pname
    p_gpt = tmp_path / "gpt.img"
    p_gpt.write_bytes(bytes(gpt))
    rep_gpt = analyze_forensic_image(p_gpt)
    assert rep_gpt["partitions"]["has_gpt"] is True
    assert any(p["name"] == "Linux RootFS" for p in rep_gpt["partitions"]["partitions"])

    # 3. Linux ext4 superblock + directory entries
    ext4 = bytearray(0x4000)
    struct.pack_into("<II", ext4, 0x400, 1024, 8192)
    struct.pack_into("<I", ext4, 0x418, 2)  # 4096 block_size
    struct.pack_into("<III", ext4, 0x420, 4096, 0, 512)
    struct.pack_into("<H", ext4, 0x438, 0xEF53)
    ext4[0x478 : 0x478 + 8] = b"rootfs_v"
    # Directory entries at block 0x1000
    struct.pack_into("<IHBB", ext4, 0x1000, 2, 12, 1, 2)
    ext4[0x1008:0x1009] = b"."
    struct.pack_into("<IHBB", ext4, 0x100C, 2, 12, 2, 2)
    ext4[0x1014:0x1016] = b".."
    struct.pack_into("<IHBB", ext4, 0x1018, 42, 4072, 10, 1)
    ext4[0x1020:0x102A] = b"implant.so"
    p_ext4 = tmp_path / "rootfs.ext4"
    p_ext4.write_bytes(bytes(ext4))
    rep_ext4 = analyze_forensic_image(p_ext4)
    assert rep_ext4["ext4"]["valid"] is True
    assert rep_ext4["ext4"]["volume_name"] == "rootfs_v"
    assert any(e["name"] == "implant.so" for e in rep_ext4["ext4"]["entries"])

    # 4. APFS + BitLocker images
    apfs = bytearray(0x2000)
    apfs[0x20:0x24] = b"NXSB"
    struct.pack_into("<IQ", apfs, 0x24, 4096, 10000)
    apfs[0x1000:0x1004] = b"APSB"
    p_apfs = tmp_path / "mac.apfs"
    p_apfs.write_bytes(bytes(apfs))
    rep_apfs = analyze_forensic_image(p_apfs)
    assert rep_apfs["apfs"]["valid"] is True and rep_apfs["apfs"]["has_volume_apsb"] is True
