"""Motor STRINGS + DECODE — melhor do ImHex (vista de bytes) + HyperDecode (auto-decode)."""

from __future__ import annotations

import base64
import binascii
import re
import string
from typing import Any
from urllib.parse import unquote_to_bytes

from aether_re.models import Finding

PRINTABLE = set(bytes(string.printable, "ascii"))
INTERESTING = re.compile(
    r"(https?://|ftp://|www\.|"
    r"[A-Za-z]:\\|"
    r"/[a-z0-9_./-]{4,}|"
    r"(cmd|powershell|bash|sh|python|perl|ruby|node)\b|"
    r"(password|passwd|secret|token|api[_-]?key|Authorization)|"
    r"(VirtualAlloc|LoadLibrary|GetProcAddress|CreateRemoteThread)|"
    r"(SELECT\s|INSERT\s|UPDATE\s|DELETE\s)|"
    r"(\.dll|\.exe|\.sys|\.bat|\.ps1|\.so|\.dylib))",
    re.I,
)


def extract_ascii_strings(data: bytes, min_len: int = 4) -> list[str]:
    out: list[str] = []
    cur = bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii", errors="ignore"))
            cur.clear()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii", errors="ignore"))
    return out


def extract_utf16le_strings(data: bytes, min_len: int = 4) -> list[str]:
    out: list[str] = []
    cur = []
    i = 0
    while i + 1 < len(data):
        lo, hi = data[i], data[i + 1]
        if hi == 0 and 32 <= lo < 127:
            cur.append(chr(lo))
            i += 2
        else:
            if len(cur) >= min_len:
                out.append("".join(cur))
            cur = []
            i += 2 if hi == 0 else 1
    if len(cur) >= min_len:
        out.append("".join(cur))
    return out


def _looks_text(b: bytes) -> bool:
    if not b or len(b) < 3:
        return False
    printable = sum(1 for x in b if x in PRINTABLE or x in (9, 10, 13))
    return (printable / len(b)) >= 0.85


def try_base64(s: str) -> bytes | None:
    t = re.sub(r"\s+", "", s)
    if len(t) < 8 or len(t) % 4 not in (0,):
        # pad
        pad = (-len(t)) % 4
        t = t + ("=" * pad)
    if not re.fullmatch(r"[A-Za-z0-9+/_-]+=*", t):
        return None
    try:
        # urlsafe variant
        alt = t.replace("-", "+").replace("_", "/")
        raw = base64.b64decode(alt, validate=False)
        return raw if raw else None
    except Exception:
        return None


def try_hex(s: str) -> bytes | None:
    t = re.sub(r"[\s:]", "", s)
    if len(t) < 8 or len(t) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", t):
        return None
    try:
        return binascii.unhexlify(t)
    except Exception:
        return None


def xor_bruteforce(data: bytes, max_len: int = 4096) -> list[dict[str, Any]]:
    sample = data[:max_len]
    if not sample:
        return []
    results: list[dict[str, Any]] = []
    for key in range(1, 256):
        dec = bytes(b ^ key for b in sample)
        if _looks_text(dec):
            preview = dec[:120].decode("latin-1", errors="replace")
            results.append(
                {
                    "algo": "xor-single-byte",
                    "key": f"0x{key:02x}",
                    "preview": preview,
                    "score": sum(1 for x in dec if x in PRINTABLE) / len(dec),
                }
            )
    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:5]


def multi_layer_decode(candidates: list[str], max_layers: int = 3) -> list[dict[str, Any]]:
    decoded: list[dict[str, Any]] = []
    seen: set[str] = set()

    for s in candidates:
        if s in seen or len(s) < 8:
            continue
        seen.add(s)
        chain: list[str] = []
        cur: str | bytes = s
        for _ in range(max_layers):
            if isinstance(cur, bytes):
                # try interpret as text for next layer
                if _looks_text(cur):
                    cur = cur.decode("utf-8", errors="ignore")
                else:
                    break
            assert isinstance(cur, str)
            b = try_base64(cur)
            if b and b not in (cur.encode(),):
                chain.append("base64")
                cur = b
                continue
            b = try_hex(cur)
            if b:
                chain.append("hex")
                cur = b
                continue
            try:
                u = unquote_to_bytes(cur)
                if u != cur.encode("latin-1", errors="ignore") and _looks_text(u):
                    chain.append("url")
                    cur = u
                    continue
            except Exception:
                pass
            break

        if chain:
            if isinstance(cur, bytes):
                preview = (
                    cur.decode("utf-8", errors="replace")
                    if _looks_text(cur)
                    else cur[:80].hex()
                )
                final_bytes = cur
            else:
                preview = cur[:200]
                final_bytes = cur.encode("utf-8", errors="ignore")
            decoded.append(
                {
                    "source": s[:80],
                    "chain": " -> ".join(chain),
                    "preview": preview[:300],
                    "xor_hints": xor_bruteforce(final_bytes) if isinstance(final_bytes, bytes) else [],
                }
            )
        else:
            # raw blob xor
            raw = s.encode("latin-1", errors="ignore")
            if len(raw) >= 16:
                xh = xor_bruteforce(raw)
                if xh and xh[0]["score"] >= 0.9:
                    decoded.append(
                        {
                            "source": s[:80],
                            "chain": "xor-heuristic",
                            "preview": xh[0]["preview"],
                            "xor_hints": xh,
                        }
                    )

    return decoded[:50]


def run_strings_decode(data: bytes, max_strings: int = 500) -> dict[str, Any]:
    ascii_s = extract_ascii_strings(data)
    utf16_s = extract_utf16le_strings(data)
    all_s = list(dict.fromkeys(ascii_s + utf16_s))

    interesting = [s for s in all_s if INTERESTING.search(s)]
    # also long base64-like
    b64ish = [
        s
        for s in all_s
        if len(s) >= 24 and re.fullmatch(r"[A-Za-z0-9+/=_-]{24,}", s)
    ]
    decode_pool = list(dict.fromkeys(interesting + b64ish))[:200]
    decoded = multi_layer_decode(decode_pool)

    # score/rank strings
    ranked = sorted(
        all_s,
        key=lambda s: (1 if INTERESTING.search(s) else 0, len(s)),
        reverse=True,
    )[:max_strings]

    findings: list[Finding] = [
        Finding(
            engine="strings_decode",
            severity="info",
            title="Extração de strings",
            detail=f"total={len(all_s)} interessantes={len(interesting)} decodificados={len(decoded)}",
            confidence=0.9,
        )
    ]
    if decoded:
        findings.append(
            Finding(
                engine="strings_decode",
                severity="medium",
                title="Payloads auto-decodificados",
                detail="; ".join(f"{d['chain']}: {d['preview'][:60]}" for d in decoded[:8]),
                confidence=0.65,
            )
        )
    for s in interesting[:15]:
        findings.append(
            Finding(
                engine="strings_decode",
                severity="low",
                title="String de interesse",
                detail=s[:200],
                confidence=0.7,
            )
        )

    return {
        "strings": ranked,
        "interesting": interesting[:100],
        "decoded_payloads": decoded,
        "findings": findings,
    }
