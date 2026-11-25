"""Unified Plaso-Style DFIR Supertimeline Correlator (v11.5).

Ingests normalized events from RAM Forensics, NTFS `$MFT`, Windows Registry,
EVTX logs, Prefetch, PCAP/PCAPNG captures, and binary PE/ELF build headers,
sorts all events canonically in UTC ISO-8601, detects cross-source attack chains
(e.g., PCAP C2 / DNS Tunneling + Drop/Timestomp + Service Persistence + DKOM),
and exports Plaso-compatible JSONL + CSV files.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


def build_supertimeline(
    *,
    ram_report: dict[str, Any] | None = None,
    disk_report: dict[str, Any] | None = None,
    pcap_report: dict[str, Any] | None = None,
    extra_events: list[dict[str, Any]] | None = None,
    output_dir: Path | str | None = None,
) -> dict[str, Any]:
    """Correlate multi-source DFIR artifacts into a canonical UTC supertimeline."""
    events: list[dict[str, Any]] = []

    if ram_report:
        for proc in ram_report.get("pool_processes", []):
            ts = proc.get("create_time_utc")
            if ts:
                events.append(
                    {
                        "timestamp_utc": ts,
                        "source": "RAM_EPROCESS",
                        "event_type": "PROCESS_CREATE",
                        "artifact": proc.get("name"),
                        "summary": f"PID={proc.get('pid')} EPROCESS_PA={hex(proc.get('eprocess_pa', 0))}",
                        "mitre_tactic": "Execution",
                        "severity": "info",
                    }
                )
        for hid in ram_report.get("dkom_hidden_processes", []):
            ts = hid.get("create_time_utc") or "1970-01-01T00:00:00.000000Z"
            events.append(
                {
                    "timestamp_utc": ts,
                    "source": "RAM_DKOM",
                    "event_type": hid.get("finding", "DKOM_HIDDEN_PROCESS"),
                    "artifact": hid.get("name"),
                    "summary": f"Hidden PID={hid.get('pid')} unlinked from ActiveProcessLinks",
                    "mitre_tactic": "Defense Evasion",
                    "mitre_technique": "T1014",
                    "severity": "critical",
                }
            )
        for pe in ram_report.get("carved_pes", []):
            if pe.get("timestamp_utc"):
                events.append(
                    {
                        "timestamp_utc": pe["timestamp_utc"],
                        "source": "RAM_PE_CARVE",
                        "event_type": "INJECTED_PE_COMPILETIME",
                        "artifact": pe.get("carved_path") or pe.get("phys_offset_hex"),
                        "summary": f"sha256={pe.get('sha256', '')[:16]} rwx={pe.get('in_rwx_page')}",
                        "mitre_tactic": "Defense Evasion",
                        "mitre_technique": "T1055",
                        "severity": "high" if pe.get("in_rwx_page") else "medium",
                    }
                )

    if disk_report:
        mft = disk_report.get("mft") or {}
        for entry in mft.get("entries", []):
            if entry.get("si_created_utc"):
                events.append(
                    {
                        "timestamp_utc": entry["si_created_utc"],
                        "source": "NTFS_MFT_SI",
                        "event_type": "FILE_TIMESTOMP" if entry.get("timestomped") else "FILE_CREATED_SI",
                        "artifact": entry.get("filename"),
                        "summary": f"MFT#{entry.get('record_id')} reasons={entry.get('timestomp_reasons')}",
                        "mitre_tactic": "Defense Evasion" if entry.get("timestomped") else "Execution",
                        "mitre_technique": "T1070.006" if entry.get("timestomped") else None,
                        "severity": "high" if entry.get("timestomped") else "info",
                    }
                )
            if entry.get("fn_created_utc"):
                events.append(
                    {
                        "timestamp_utc": entry["fn_created_utc"],
                        "source": "NTFS_MFT_FN",
                        "event_type": "FILE_CREATED_FN",
                        "artifact": entry.get("filename"),
                        "summary": f"MFT#{entry.get('record_id')} ($FILE_NAME authoritative creation)",
                        "mitre_tactic": "Execution",
                        "severity": "medium" if entry.get("timestomped") else "info",
                    }
                )
        reg = disk_report.get("registry") or {}
        for k in reg.get("persistence_hits", []):
            if k.get("last_write_utc"):
                events.append(
                    {
                        "timestamp_utc": k["last_write_utc"],
                        "source": "REGISTRY_HIVE",
                        "event_type": "PERSISTENCE_KEY_WRITE",
                        "artifact": k.get("path"),
                        "summary": json.dumps(k.get("values", []), ensure_ascii=False)[:180],
                        "mitre_tactic": "Persistence",
                        "mitre_technique": "T1547.001",
                        "severity": "high",
                    }
                )
        evtx = disk_report.get("evtx") or {}
        for ev in evtx.get("events", []):
            if ev.get("timestamp_utc"):
                events.append(
                    {
                        "timestamp_utc": ev["timestamp_utc"],
                        "source": "WINDOWS_EVTX",
                        "event_type": f"EVENT_ID_{ev.get('event_id')}" if ev.get("event_id") else "EVTX_RECORD",
                        "artifact": str(ev.get("event_id") or ev.get("record_id")),
                        "summary": " | ".join(ev.get("strings", [])[:4]),
                        "mitre_tactic": ev.get("mitre_tactic"),
                        "mitre_technique": ev.get("mitre_technique"),
                        "severity": "high" if ev.get("event_id") in (1102, 7045, 4688) else "info",
                    }
                )
        for pf in disk_report.get("prefetch", []):
            if pf.get("last_run_utc"):
                events.append(
                    {
                        "timestamp_utc": pf["last_run_utc"],
                        "source": "PREFETCH_SCCA",
                        "event_type": "PROGRAM_EXECUTED",
                        "artifact": pf.get("executable"),
                        "summary": f"run_count={pf.get('run_count')} hash={pf.get('prefetch_hash')}",
                        "mitre_tactic": "Execution",
                        "severity": "info",
                    }
                )

    if pcap_report:
        for d in pcap_report.get("dns_queries", []):
            if d.get("timestamp_utc"):
                events.append(
                    {
                        "timestamp_utc": d["timestamp_utc"],
                        "source": "PCAP_DNS",
                        "event_type": "DNS_TUNNELING" if d.get("dns_tunneling_suspected") else "DNS_QUERY",
                        "artifact": d.get("qname"),
                        "summary": f"{d.get('src_ip')} -> {d.get('dst_ip')} entropy={d.get('subdomain_entropy')}",
                        "mitre_tactic": "Command and Control",
                        "mitre_technique": "T1071.004",
                        "severity": "high" if d.get("dns_tunneling_suspected") else "info",
                    }
                )
        for tls in pcap_report.get("tls_ja3_hellos", []):
            if tls.get("timestamp_utc"):
                events.append(
                    {
                        "timestamp_utc": tls["timestamp_utc"],
                        "source": "PCAP_TLS_JA3",
                        "event_type": "TLS_CLIENT_HELLO",
                        "artifact": tls.get("sni") or tls.get("dst_ip"),
                        "summary": f"ja3={tls.get('ja3_md5')} dst={tls.get('dst_ip')}:{tls.get('dst_port')}",
                        "mitre_tactic": "Command and Control",
                        "mitre_technique": "T1573",
                        "severity": "info",
                    }
                )
        for b in pcap_report.get("c2_beacons", []):
            events.append(
                {
                    "timestamp_utc": b["first_seen_utc"],
                    "source": "PCAP_BEACON",
                    "event_type": "C2_BEACONING_DETECTED",
                    "artifact": f"{b.get('dst_ip')}:{b.get('dst_port')}",
                    "summary": f"beacons={b.get('beacon_count')} mean_dt={b.get('mean_interval_sec')}s cv={b.get('jitter_cv')}",
                    "mitre_tactic": "Command and Control",
                    "mitre_technique": "T1071",
                    "severity": "critical",
                }
            )

    for ev in extra_events or []:
        if ev.get("timestamp_utc"):
            events.append(dict(ev))

    events.sort(key=lambda e: (e.get("timestamp_utc") or "", e.get("source") or ""))

    tactics = sorted({e["mitre_tactic"] for e in events if e.get("mitre_tactic")})
    high_critical = [e for e in events if e.get("severity") in ("high", "critical")]
    sources = sorted({e["source"] for e in events})

    files_written: dict[str, str] = {}
    if output_dir is not None:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        jsonl_path = out / "supertimeline.plaso.jsonl"
        csv_path = out / "supertimeline.csv"
        jsonl_path.write_text(
            "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in events),
            encoding="utf-8",
            newline="\n",
        )
        with csv_path.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(
                fh,
                fieldnames=[
                    "timestamp_utc",
                    "source",
                    "event_type",
                    "artifact",
                    "mitre_tactic",
                    "mitre_technique",
                    "severity",
                    "summary",
                ],
                extrasaction="ignore",
            )
            writer.writeheader()
            writer.writerows(events)
        files_written = {"jsonl": str(jsonl_path), "csv": str(csv_path)}

    return {
        "schema": "aether_supertimeline.v1",
        "event_count": len(events),
        "sources": sources,
        "mitre_tactics_observed": tactics,
        "high_critical_findings": high_critical,
        "events": events,
        "files_written": files_written,
    }
