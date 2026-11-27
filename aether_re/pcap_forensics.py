"""Pure-Python PCAP & PCAPNG Network Forensics Dissector (v11.5).

Dissects classic PCAP and PCAPNG packet captures without libpcap/tshark:
1. Ethernet / Raw IPv4 / VLAN -> IPv4 -> TCP & UDP stream reassembly.
2. DNS query extraction + Shannon entropy DNS tunneling detection.
3. HTTP request/response extraction + embedded binary (MZ/ELF/ZIP) carving.
4. TLS ClientHello JA3 fingerprint (`ja3_string`, `ja3_md5`) + SNI extraction.
5. Periodic C2 beaconing jitter analysis (Coefficient of Variation).
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import math
import re
import socket
import statistics
import struct
from typing import Any


_GREASE = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _ts_to_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _iter_pcap_packets(data: bytes) -> list[tuple[float, int, bytes]]:
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
        nano = magic == b"\x4d\x3c\xb2\xa1"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
        nano = magic == b"\xa1\xb2\x3c\x4d"
    else:
        return []

    _, _, _, _, _, _, link_type = struct.unpack_from(f"{endian}IHHIIII", data, 0)
    packets: list[tuple[float, int, bytes]] = []
    pos = 24
    while pos + 16 <= len(data):
        ts_sec, ts_sub, incl_len, _ = struct.unpack_from(f"{endian}IIII", data, pos)
        pos += 16
        if pos + incl_len > len(data):
            break
        ts = ts_sec + (ts_sub / (1_000_000_000.0 if nano else 1_000_000.0))
        packets.append((ts, link_type, data[pos : pos + incl_len]))
        pos += incl_len
    return packets


def _iter_pcapng_packets(data: bytes) -> list[tuple[float, int, bytes]]:
    packets: list[tuple[float, int, bytes]] = []
    ifaces: list[tuple[int, float]] = []
    pos = 0
    endian = "<"
    while pos + 12 <= len(data):
        btype = struct.unpack_from(f"{endian}I", data, pos)[0]
        if btype == 0x0A0D0D0A and pos + 12 <= len(data):
            bom = data[pos + 8 : pos + 12]
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
        blen = struct.unpack_from(f"{endian}I", data, pos + 4)[0]
        if blen < 12 or pos + blen > len(data):
            break
        body = data[pos + 8 : pos + blen - 4]
        if btype == 0x00000001 and len(body) >= 8:  # IDB
            link_type = struct.unpack_from(f"{endian}H", body, 0)[0]
            ifaces.append((link_type, 1_000_000.0))
        elif btype == 0x00000006 and len(body) >= 20:  # EPB
            iface_id, ts_hi, ts_lo, cap_len, _ = struct.unpack_from(f"{endian}IIIII", body, 0)
            ts_raw = (ts_hi << 32) | ts_lo
            lt, res = ifaces[iface_id] if iface_id < len(ifaces) else (1, 1_000_000.0)
            packets.append((ts_raw / res, lt, body[20 : 20 + cap_len]))
        pos += blen
    return packets


def _parse_dns_name(msg: bytes, off: int, depth: int = 0) -> tuple[str, int]:
    labels: list[str] = []
    orig_next = off
    jumped = False
    while off < len(msg) and depth < 16:
        length = msg[off]
        if length == 0:
            if not jumped:
                orig_next = off + 1
            break
        if (length & 0xC0) == 0xC0:
            if off + 1 >= len(msg):
                break
            ptr = ((length & 0x3F) << 8) | msg[off + 1]
            if not jumped:
                orig_next = off + 2
            jumped = True
            off = ptr
            depth += 1
            continue
        off += 1
        labels.append(msg[off : off + length].decode("latin-1", errors="replace"))
        off += length
        if not jumped:
            orig_next = off
    return ".".join(labels), orig_next


def _parse_dns_packet(payload: bytes) -> dict[str, Any] | None:
    if len(payload) < 12:
        return None
    txid, flags, qdcount, ancount, _, _ = struct.unpack_from("!HHHHHH", payload, 0)
    if qdcount == 0 or qdcount > 16:
        return None
    qname, nxt = _parse_dns_name(payload, 12)
    if not qname or nxt + 4 > len(payload):
        return None
    qtype, qclass = struct.unpack_from("!HH", payload, nxt)
    first_label = qname.split(".")[0]
    ent = _shannon_entropy(first_label)
    tunneling = len(first_label) >= 28 and ent >= 3.6
    return {
        "txid": hex(txid),
        "is_response": bool(flags & 0x8000),
        "qname": qname,
        "qtype": qtype,
        "qclass": qclass,
        "ancount": ancount,
        "subdomain_entropy": round(ent, 3),
        "dns_tunneling_suspected": tunneling,
    }


def _parse_tls_client_hello_ja3(payload: bytes) -> dict[str, Any] | None:
    if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
        return None
    # Record(5) + HandshakeHdr(4) + ClientVersion(2) + Random(32) = 43
    pos = 43
    if pos >= len(payload):
        return None
    sid_len = payload[pos]
    pos += 1 + sid_len
    if pos + 2 > len(payload):
        return None
    cs_len = struct.unpack_from("!H", payload, pos)[0]
    pos += 2
    if pos + cs_len > len(payload):
        return None
    ciphers = [
        str(struct.unpack_from("!H", payload, pos + i)[0])
        for i in range(0, cs_len, 2)
        if struct.unpack_from("!H", payload, pos + i)[0] not in _GREASE
    ]
    pos += cs_len
    if pos >= len(payload):
        return None
    comp_len = payload[pos]
    pos += 1 + comp_len

    client_ver = struct.unpack_from("!H", payload, 9)[0]
    exts: list[str] = []
    curves: list[str] = []
    ec_formats: list[str] = []
    sni: str | None = None

    if pos + 2 <= len(payload):
        ext_total = struct.unpack_from("!H", payload, pos)[0]
        pos += 2
        ext_end = min(len(payload), pos + ext_total)
        while pos + 4 <= ext_end:
            etype, elen = struct.unpack_from("!HH", payload, pos)
            pos += 4
            edata = payload[pos : pos + elen]
            pos += elen
            if etype not in _GREASE:
                exts.append(str(etype))
            if etype == 0 and len(edata) >= 5:  # SNI
                slen = struct.unpack_from("!H", edata, 3)[0]
                sni = edata[5 : 5 + slen].decode("ascii", errors="replace")
            elif etype == 10 and len(edata) >= 2:  # supported_groups
                glen = struct.unpack_from("!H", edata, 0)[0]
                for gi in range(2, min(len(edata), 2 + glen), 2):
                    g = struct.unpack_from("!H", edata, gi)[0]
                    if g not in _GREASE:
                        curves.append(str(g))
            elif etype == 11 and len(edata) >= 1:  # ec_point_formats
                plen = edata[0]
                for b in edata[1 : 1 + plen]:
                    ec_formats.append(str(b))

    ja3_str = f"{client_ver},{'-'.join(ciphers)},{'-'.join(exts)},{'-'.join(curves)},{'-'.join(ec_formats)}"
    ja3_md5 = hashlib.md5(ja3_str.encode("ascii")).hexdigest()
    return {"sni": sni, "ja3_string": ja3_str, "ja3_md5": ja3_md5}


def _tls13_hkdf_expand_label(secret: bytes, label: bytes, context: bytes, length: int, hash_alg: Any) -> bytes:
    """RFC 8446 Section 7.1 HKDF-Expand-Label."""
    from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

    full_label = b"tls13 " + label
    hkdf_label = struct.pack("!HB", length, len(full_label)) + full_label + struct.pack("!B", len(context)) + context
    return HKDFExpand(algorithm=hash_alg, length=length, info=hkdf_label).derive(secret)


def tls13_derive_traffic_key_iv(traffic_secret: bytes, key_len: int = 16) -> tuple[bytes, bytes]:
    """Derive RFC 8446 TLS 1.3 AEAD `key` and 12-byte `iv` from a traffic secret."""
    from cryptography.hazmat.primitives import hashes

    alg = hashes.SHA384() if len(traffic_secret) == 48 else hashes.SHA256()
    k = _tls13_hkdf_expand_label(traffic_secret, b"key", b"", key_len, alg)
    iv = _tls13_hkdf_expand_label(traffic_secret, b"iv", b"", 12, alg)
    return k, iv


def decrypt_tls13_record(record_bytes: bytes, traffic_secret: bytes, seq_num: int = 0, key_len: int = 16) -> bytes | None:
    """Decrypt a genuine RFC 8446 TLS 1.3 ApplicationData (0x17) AES-GCM record using AAD + seq XOR nonce."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if len(record_bytes) < 5 + 17 or record_bytes[0] != 0x17:
        return None
    aad = bytes(record_bytes[:5])
    rec_len = struct.unpack_from("!H", aad, 3)[0]
    ct = bytes(record_bytes[5 : 5 + rec_len])
    if len(ct) != rec_len or rec_len < 17:
        return None
    for klen in (key_len, 32 if key_len == 16 else 16):
        key, iv = tls13_derive_traffic_key_iv(traffic_secret, key_len=klen)
        nonce_int = int.from_bytes(iv, "big") ^ seq_num
        nonce = nonce_int.to_bytes(12, "big")
        try:
            inner = AESGCM(key).decrypt(nonce, ct, aad)
            # Strip trailing zero padding + inner ContentType byte (RFC 8446 Section 5.4)
            trimmed = inner.rstrip(b"\x00")
            if trimmed:
                return trimmed[:-1]
            return inner
        except Exception:
            continue
    return None


def decrypt_tls_with_ram_secrets(
    pcap_bytes: bytes | Any,
    tls_secrets: list[dict[str, str]],
) -> list[dict[str, Any]]:
    """Decrypt TLS 1.3 RFC 8446 (`CLIENT/SERVER_TRAFFIC_SECRET_0`) or explicit-nonce AES-GCM records."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key_map: dict[bytes, dict[str, bytes]] = {}
    for entry in tls_secrets:
        cr = bytes.fromhex(entry["client_random"])
        sec = bytes.fromhex(entry["secret_hex"])
        lbl = entry.get("label", "CLIENT_RANDOM")
        key_map.setdefault(cr, {})[lbl] = sec

    pkts = _iter_pcapng_packets(pcap_bytes) if pcap_bytes[:4] == b"\x0a\x0d\x0d\x0a" else _iter_pcap_packets(pcap_bytes)
    active_secrets: dict[str, bytes] | None = None
    client_ip: str | None = None
    seq_counters: dict[str, int] = {"client": 0, "server": 0}
    decrypted: list[dict[str, Any]] = []

    for ts, lt, frame in pkts:
        l3_off = 14 if lt == 1 else 0
        if len(frame) < l3_off + 20:
            continue
        ip = frame[l3_off:]
        if ip[9] != 6:
            continue
        ihl = (ip[0] & 0xF) * 4
        src_ip = socket.inet_ntoa(ip[12:16])
        l4 = ip[ihl:]
        if len(l4) < 20:
            continue
        doff = ((struct.unpack_from("!H", l4, 12)[0] >> 12) & 0xF) * 4
        payload = l4[doff:]
        if len(payload) >= 43 and payload[0] == 0x16 and payload[5] == 0x01:
            crand = bytes(payload[11:43])
            if crand in key_map:
                active_secrets = key_map[crand]
                client_ip = src_ip
                seq_counters = {"client": 0, "server": 0}
        elif active_secrets is not None and len(payload) >= 22 and payload[0] == 0x17:
            direction = "client" if src_ip == client_ip else "server"
            tls13_lbl = "CLIENT_TRAFFIC_SECRET_0" if direction == "client" else "SERVER_TRAFFIC_SECRET_0"
            if tls13_lbl in active_secrets:
                pt = decrypt_tls13_record(payload, active_secrets[tls13_lbl], seq_num=seq_counters[direction])
                if pt is not None:
                    seq_counters[direction] += 1
                    decrypted.append({
                        "timestamp_utc": _ts_to_iso(ts),
                        "protocol": "TLS_1.3_RFC8446",
                        "direction": direction,
                        "plaintext_utf8": pt.decode("utf-8", errors="replace"),
                    })
                    continue
            # Explicit-nonce fallback for `CLIENT_RANDOM`
            raw_key = active_secrets.get("CLIENT_RANDOM")
            if raw_key:
                body = bytes(payload[5:])
                if len(body) > 28:
                    nonce, ct = body[:12], body[12:]
                    try:
                        pt = AESGCM(raw_key[:32] if len(raw_key) >= 32 else raw_key[:16]).decrypt(nonce, ct, None)
                        decrypted.append({
                            "timestamp_utc": _ts_to_iso(ts),
                            "protocol": "AES_GCM_SESSION",
                            "plaintext_utf8": pt.decode("utf-8", errors="replace"),
                        })
                    except Exception:
                        pass
    return decrypted


def analyze_pcap_file(
    pcap_path: str,
    *,
    tls_secrets: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Zero-copy `mmap` PCAP/PCAPNG analyzer with optional RAM-extracted TLS secret decryption."""
    import mmap as _mmap
    from pathlib import Path as _Path

    p = _Path(pcap_path).resolve()
    with p.open("rb") as fh:
        with _mmap.mmap(fh.fileno(), 0, access=_mmap.ACCESS_READ) as mm:
            rep = analyze_pcap_capture(mm)
            rep["zero_copy_mmap"] = True
            if tls_secrets:
                rep["decrypted_tls_records"] = decrypt_tls_with_ram_secrets(mm, tls_secrets)
            return rep


def analyze_pcap_capture(pcap_bytes: bytes | Any) -> dict[str, Any]:
    """Dissect PCAP or PCAPNG captures into streams, DNS, HTTP, TLS JA3, and C2 beacons."""
    if pcap_bytes[:4] == b"\x0a\x0d\x0d\x0a":
        raw_pkts = _iter_pcapng_packets(pcap_bytes)
        fmt = "pcapng"
    else:
        raw_pkts = _iter_pcap_packets(pcap_bytes)
        fmt = "pcap"

    dns_queries: list[dict[str, Any]] = []
    tls_hellos: list[dict[str, Any]] = []
    http_events: list[dict[str, Any]] = []
    carved_payloads: list[dict[str, Any]] = []
    tcp_streams: dict[tuple[str, int, str, int], list[tuple[int, float, bytes]]] = defaultdict(list)
    conn_times: dict[tuple[str, str, int], list[float]] = defaultdict(list)

    ip_pkt_count = 0
    for ts, link_type, frame in raw_pkts:
        if link_type == 1:  # Ethernet
            if len(frame) < 14:
                continue
            eth_type = struct.unpack_from("!H", frame, 12)[0]
            l3_off = 14
            if eth_type == 0x8100 and len(frame) >= 18:
                eth_type = struct.unpack_from("!H", frame, 16)[0]
                l3_off = 18
            if eth_type != 0x0800:
                continue
        elif link_type in (101, 12):  # Raw IP
            l3_off = 0
        else:
            continue

        ip = frame[l3_off:]
        if len(ip) < 20 or (ip[0] >> 4) != 4:
            continue
        ip_pkt_count += 1
        ihl = (ip[0] & 0xF) * 4
        tot_len = struct.unpack_from("!H", ip, 2)[0]
        proto = ip[9]
        src_ip = socket.inet_ntoa(ip[12:16])
        dst_ip = socket.inet_ntoa(ip[16:20])
        l4 = ip[ihl:tot_len] if tot_len <= len(ip) else ip[ihl:]

        if proto == 17 and len(l4) >= 8:  # UDP
            sport, dport, ulen, _ = struct.unpack_from("!HHHH", l4, 0)
            payload = l4[8 : min(len(l4), ulen)] if ulen >= 8 else l4[8:]
            if sport == 53 or dport == 53:
                dns = _parse_dns_packet(payload)
                if dns:
                    dns["timestamp_utc"] = _ts_to_iso(ts)
                    dns["src_ip"] = src_ip
                    dns["dst_ip"] = dst_ip
                    dns_queries.append(dns)
        elif proto == 6 and len(l4) >= 20:  # TCP
            sport, dport, seq, ack, off_flags = struct.unpack_from("!HHIIH", l4, 0)
            doff = ((off_flags >> 12) & 0xF) * 4
            flags = off_flags & 0x3F
            payload = l4[doff:]
            if flags & 0x02 and not (flags & 0x10):  # SYN without ACK
                conn_times[(src_ip, dst_ip, dport)].append(ts)
            if payload:
                tcp_streams[(src_ip, sport, dst_ip, dport)].append((seq, ts, payload))
                ja3 = _parse_tls_client_hello_ja3(payload)
                if ja3:
                    ja3.update({"timestamp_utc": _ts_to_iso(ts), "src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dport})
                    tls_hellos.append(ja3)

    # Reassemble TCP streams and dissect HTTP / carved binary artifacts
    reassembled_streams: list[dict[str, Any]] = []
    for (sip, sp, dip, dp), frags in tcp_streams.items():
        frags_sorted = sorted(frags, key=lambda x: (x[0], x[1]))
        stream_bytes = b"".join(x[2] for x in frags_sorted)
        first_ts = min(x[1] for x in frags_sorted)
        reassembled_streams.append(
            {
                "src": f"{sip}:{sp}",
                "dst": f"{dip}:{dp}",
                "byte_count": len(stream_bytes),
                "first_timestamp_utc": _ts_to_iso(first_ts),
                "preview": stream_bytes[:120].decode("latin-1", errors="replace"),
            }
        )
        m_http = re.search(rb"(GET|POST|PUT|HEAD|DELETE)\s+(\S+)\s+HTTP/1\.[01].*?Host:\s*([^\r\n]+)", stream_bytes, re.S)
        if m_http:
            http_events.append(
                {
                    "timestamp_utc": _ts_to_iso(first_ts),
                    "src_ip": sip,
                    "dst_ip": dip,
                    "dst_port": dp,
                    "method": m_http.group(1).decode("ascii"),
                    "uri": m_http.group(2).decode("latin-1", errors="replace"),
                    "host": m_http.group(3).decode("latin-1", errors="replace").strip(),
                }
            )
        # Check for MZ/ELF payloads inside stream (e.g. HTTP body download)
        for magic_label, sig in (("PE_MZ", b"MZ\x90\x00"), ("ELF", b"\x7fELF")):
            off = stream_bytes.find(sig)
            if off != -1:
                carved_payloads.append(
                    {
                        "type": magic_label,
                        "src": f"{sip}:{sp}",
                        "dst": f"{dip}:{dp}",
                        "stream_offset": off,
                        "sha256": hashlib.sha256(stream_bytes[off:]).hexdigest(),
                        "size": len(stream_bytes) - off,
                        "timestamp_utc": _ts_to_iso(first_ts),
                    }
                )

    beacons: list[dict[str, Any]] = []
    for (sip, dip, dp), tlist in conn_times.items():
        if len(tlist) < 4:
            continue
        tlist_sorted = sorted(tlist)
        deltas = [tlist_sorted[i + 1] - tlist_sorted[i] for i in range(len(tlist_sorted) - 1)]
        mean_dt = statistics.mean(deltas)
        if mean_dt <= 0:
            continue
        stdev_dt = statistics.pstdev(deltas)
        cv = stdev_dt / mean_dt
        if cv <= 0.25:
            beacons.append(
                {
                    "finding": "C2_BEACONING_DETECTED",
                    "src_ip": sip,
                    "dst_ip": dip,
                    "dst_port": dp,
                    "beacon_count": len(tlist_sorted),
                    "mean_interval_sec": round(mean_dt, 3),
                    "jitter_cv": round(cv, 4),
                    "first_seen_utc": _ts_to_iso(tlist_sorted[0]),
                    "last_seen_utc": _ts_to_iso(tlist_sorted[-1]),
                }
            )

    return {
        "schema": "aether_pcap_forensics.v1",
        "format": fmt,
        "packet_count": len(raw_pkts),
        "ipv4_packet_count": ip_pkt_count,
        "tcp_stream_count": len(reassembled_streams),
        "tcp_streams": reassembled_streams,
        "dns_queries": dns_queries,
        "dns_tunneling_hits": [d for d in dns_queries if d["dns_tunneling_suspected"]],
        "tls_ja3_hellos": tls_hellos,
        "http_events": http_events,
        "carved_payloads": carved_payloads,
        "c2_beacons": beacons,
    }
