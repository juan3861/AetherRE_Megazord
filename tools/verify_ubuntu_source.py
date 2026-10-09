"""Verifica integridade do .vhd local contra o .vhd dentro do tarball oficial.

Fluxo somente-leitura: nao extrai nada para disco; faz streaming do membro do
tar e calcula SHA-256 incremental. Compara com o hash do arquivo local.
"""
from __future__ import annotations

import hashlib
import json
import sys
import tarfile
import time
from pathlib import Path

TARBALL = Path(r"E:\AetherRE_DynamicLab\ubuntu-noble-20260926\noble-server-cloudimg-amd64-azure.vhd.tar.gz")
MEMBER = "livecd.ubuntu-cpc.azure.vhd"
LOCAL = Path(r"E:\AetherRE_DynamicLab\vm-images\ubuntu-noble-20260926\livecd.ubuntu-cpc.azure.vhd")
MATERIALIZED = Path(r"E:\AetherRE_DynamicLab\materialized-parents\6e01c68d4a1940b4\ubuntu-noble-parent-fixed.vhd")
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else None


def hash_stream(handle, total_hint: int = 0, label: str = "") -> str:
    digest = hashlib.sha256()
    read = 0
    started = time.time()
    while True:
        chunk = handle.read(1 << 22)
        if not chunk:
            break
        digest.update(chunk)
        read += len(chunk)
        if total_hint and read % (1 << 30) < (1 << 22):
            pct = 100.0 * read / total_hint
            rate = read / max(time.time() - started, 1e-6) / (1 << 20)
            print(f"  {label}: {read/(1<<30):.1f} GiB ({pct:.1f}%) {rate:.0f} MiB/s", flush=True)
    return digest.hexdigest()


def hash_file(path: Path) -> str:
    with path.open("rb") as handle:
        return hash_stream(handle, path.stat().st_size, path.name)


def hash_tar_member(path: Path, member: str) -> tuple[str, int]:
    with tarfile.open(path, "r:gz") as tar:
        info = tar.getmember(member)
        handle = tar.extractfile(info)
        if handle is None:
            raise SystemExit(f"membro {member} nao extraivel")
        return hash_stream(handle, info.size, member), info.size


def main() -> int:
    report: dict[str, object] = {"schema": "ubuntu-source-integrity.v1"}
    print("[1/3] hash do membro dentro do tarball oficial ...", flush=True)
    tar_hash, tar_size = hash_tar_member(TARBALL, MEMBER)
    report["tar_member"] = {"name": MEMBER, "size": tar_size, "sha256": tar_hash}
    print(f"  -> {tar_hash}  ({tar_size} bytes)", flush=True)

    print("[2/3] hash do .vhd local extraido ...", flush=True)
    local_hash = hash_file(LOCAL)
    report["local_extracted"] = {"path": str(LOCAL), "size": LOCAL.stat().st_size,
                                 "sha256": local_hash}
    print(f"  -> {local_hash}", flush=True)

    print("[3/3] hash do .vhd materializado (pai denso) ...", flush=True)
    mat_hash = hash_file(MATERIALIZED)
    report["materialized"] = {"path": str(MATERIALIZED),
                              "size": MATERIALIZED.stat().st_size,
                              "sha256": mat_hash}
    print(f"  -> {mat_hash}", flush=True)

    report["tar_matches_local"] = tar_hash == local_hash
    report["local_matches_materialized"] = local_hash == mat_hash
    report["verdict"] = ("source_intact" if tar_hash == local_hash
                         else "local_extracted_diverges_from_official_tarball")
    if OUT:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
                       encoding="utf-8", newline="\n")
    print(json.dumps({k: report[k] for k in
                      ("tar_matches_local", "local_matches_materialized", "verdict")},
                     indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
