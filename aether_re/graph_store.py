"""Persistência local, transacional e verificável para o grafo de análise.

O grafo é uma projeção dos relatórios brutos: não substitui os artefatos nem
transforma uma aresta inferida em fato. O store usa apenas SQLite da biblioteca
padrão, rejeita conflitos de identidade e publica hashes dos payloads. Nenhum
import do projeto analisado, build ou alvo é executado.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from pathlib import Path
from typing import Any


SCHEMA = "graph-store.v1"
_GRAPH_SCHEMAS = {"source-graph.v1", "binary-graph.v1", "trace-graph.v1", "graph.v1", "forensic-graph.v2"}
_LIMITATIONS = [
    "o store é uma projeção; relatórios brutos continuam sendo a fonte de evidência",
    "arestas inferidas permanecem inferidas e não provam causalidade ou equivalência",
    "SQLite local não fornece custódia externa, assinatura ou coordenação distribuída",
]


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _invalid(errors: list[dict[str, Any]], *, db: Path | None = None) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "status": "invalid",
        "db": str(db) if db is not None else None,
        "inserted_nodes": 0,
        "inserted_edges": 0,
        "deduplicated_edges": 0,
        "errors": errors,
        "stats": {"nodes": 0, "edges": 0},
        "limitations": list(_LIMITATIONS),
    }


def _validate_db_path(db_path: Path, *, create_parent: bool = True) -> tuple[Path | None, list[dict[str, Any]]]:
    try:
        path = Path(db_path)
    except (TypeError, ValueError):
        return None, [{"code": "db_path_invalid"}]
    if path.exists() and path.is_symlink():
        return None, [{"code": "db_symlink_not_allowed"}]
    try:
        absolute = Path(os.path.abspath(str(path)))
        current = Path(absolute.anchor)
        for component in absolute.parts[1:]:
            current = current / component
            if current == absolute:
                break
            if current.is_symlink():
                return None, [{"code": "db_parent_symlink_not_allowed"}]
        if create_parent:
            path.parent.mkdir(parents=True, exist_ok=True)
        elif not path.parent.is_dir():
            return None, [{"code": "db_parent_missing"}]
        return path.resolve(), []
    except (OSError, RuntimeError):
        return None, [{"code": "db_path_unwritable"}]


def _connect(db_path: Path, *, initialize: bool = True) -> sqlite3.Connection:
    connection = sqlite3.connect(str(db_path), timeout=10.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=10000")
    if initialize:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS graph_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS graph_nodes (
                node_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS graph_edges (
                edge_id TEXT PRIMARY KEY,
                source_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                payload_sha256 TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_graph_edges_source ON graph_edges(source_id);
            CREATE INDEX IF NOT EXISTS idx_graph_edges_target ON graph_edges(target_id);
            """
        )
        connection.execute("INSERT OR IGNORE INTO graph_metadata(key, value) VALUES('schema', ?)", (SCHEMA,))
        connection.commit()
    return connection


def _stats(connection: sqlite3.Connection) -> dict[str, int]:
    nodes = int(connection.execute("SELECT COUNT(*) FROM graph_nodes").fetchone()[0])
    edges = int(connection.execute("SELECT COUNT(*) FROM graph_edges").fetchone()[0])
    return {"nodes": nodes, "edges": edges}


def _normalise_graph(document: Any) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    if not isinstance(document, dict):
        return None, [{"code": "graph_input_must_be_object"}]
    graph = document.get("graph", document)
    if not isinstance(graph, dict):
        return None, [{"code": "graph_must_be_object"}]
    graph_schema = graph.get("schema")
    if graph_schema not in _GRAPH_SCHEMAS:
        return None, [{"code": "graph_schema_invalid", "received": graph_schema}]
    nodes = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list):
        return None, [{"code": "graph_nodes_edges_must_be_lists"}]
    return {"schema": graph_schema, "nodes": nodes, "edges": edges}, []


def ingest_graph(
    db_path: Path,
    document: Any,
    *,
    run_id: str = "",
    max_nodes: int = 100_000,
    max_edges: int = 300_000,
) -> dict[str, Any]:
    """Atomically ingest a bounded graph projection into SQLite."""
    resolved_db, path_errors = _validate_db_path(db_path, create_parent=True)
    if path_errors:
        return _invalid(path_errors, db=Path(db_path) if isinstance(db_path, (str, Path)) else None)
    if isinstance(run_id, str) is False or not run_id.strip():
        return _invalid([{"code": "run_id_invalid"}], db=resolved_db)
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 1 for value in (max_nodes, max_edges)):
        return _invalid([{"code": "graph_budget_invalid"}], db=resolved_db)
    graph, errors = _normalise_graph(document)
    if errors or graph is None:
        return _invalid(errors, db=resolved_db)
    nodes = graph["nodes"]
    edges = graph["edges"]
    if len(nodes) > max_nodes or len(edges) > max_edges:
        return _invalid([{"code": "graph_budget_exceeded", "nodes": len(nodes), "edges": len(edges), "max_nodes": max_nodes, "max_edges": max_edges}], db=resolved_db)
    local_errors: list[dict[str, Any]] = []
    node_rows: list[tuple[str, str, str, str]] = []
    node_ids: set[str] = set()
    for index, node in enumerate(nodes):
        if not isinstance(node, dict):
            local_errors.append({"index": index, "code": "node_not_object"})
            continue
        node_id = node.get("id")
        kind = node.get("kind")
        if not isinstance(node_id, str) or not node_id.strip():
            local_errors.append({"index": index, "code": "node_id_invalid"})
            continue
        if not isinstance(kind, str) or not kind.strip():
            local_errors.append({"index": index, "code": "node_kind_invalid", "node_id": node_id})
            continue
        if node_id in node_ids:
            local_errors.append({"index": index, "code": "duplicate_node_id", "node_id": node_id})
            continue
        node_ids.add(node_id)
        try:
            payload_json = _canonical(node)
        except (TypeError, ValueError):
            local_errors.append({"index": index, "code": "node_not_serializable", "node_id": node_id})
            continue
        node_rows.append((node_id, kind, payload_json, hashlib.sha256(payload_json.encode("utf-8")).hexdigest()))
    edge_rows: list[tuple[str, str, str, str, str, str]] = []
    edge_ids: set[str] = set()
    deduplicated_edges = 0
    for index, edge in enumerate(edges):
        if not isinstance(edge, dict):
            local_errors.append({"index": index, "code": "edge_not_object"})
            continue
        source_id = edge.get("source")
        target_id = edge.get("target")
        kind = edge.get("kind")
        if any(not isinstance(value, str) or not value.strip() for value in (source_id, target_id, kind)):
            local_errors.append({"index": index, "code": "edge_identity_invalid"})
            continue
        try:
            payload_json = _canonical(edge)
        except (TypeError, ValueError):
            local_errors.append({"index": index, "code": "edge_not_serializable"})
            continue
        edge_id = _digest({"source": source_id, "target": target_id, "kind": kind, "payload": edge})
        if edge_id in edge_ids:
            # Exact duplicate observations do not add evidence. Deduplicate
            # them instead of failing the whole source graph, while preserving
            # distinct payloads (for example, different callsites).
            deduplicated_edges += 1
            continue
        edge_ids.add(edge_id)
        edge_rows.append((edge_id, source_id, target_id, kind, payload_json, hashlib.sha256(payload_json.encode("utf-8")).hexdigest()))
    if local_errors:
        return _invalid(local_errors, db=resolved_db)
    connection: sqlite3.Connection | None = None
    try:
        connection = _connect(resolved_db)
        inserted_nodes = 0
        inserted_edges = 0
        with connection:
            connection.execute("INSERT OR REPLACE INTO graph_metadata(key, value) VALUES('last_run_id', ?)", (run_id.strip(),))
            connection.execute("INSERT OR REPLACE INTO graph_metadata(key, value) VALUES('last_graph_schema', ?)", (graph["schema"],))
            for row in node_rows:
                existing = connection.execute("SELECT payload_sha256 FROM graph_nodes WHERE node_id = ?", (row[0],)).fetchone()
                if existing is not None and existing[0] != row[3]:
                    raise ValueError(f"node_identity_conflict:{row[0]}")
                cursor = connection.execute("INSERT OR IGNORE INTO graph_nodes(node_id, kind, payload_json, payload_sha256) VALUES(?, ?, ?, ?)", row)
                inserted_nodes += int(cursor.rowcount > 0)
            for row in edge_rows:
                existing = connection.execute("SELECT payload_sha256 FROM graph_edges WHERE edge_id = ?", (row[0],)).fetchone()
                if existing is not None and existing[0] != row[5]:
                    raise ValueError(f"edge_identity_conflict:{row[0]}")
                cursor = connection.execute("INSERT OR IGNORE INTO graph_edges(edge_id, source_id, target_id, kind, payload_json, payload_sha256) VALUES(?, ?, ?, ?, ?, ?)", row)
                inserted_edges += int(cursor.rowcount > 0)
        stats = _stats(connection)
        return {"schema": SCHEMA, "status": "complete", "db": str(resolved_db), "run_id": run_id.strip(), "graph_schema": graph["schema"], "inserted_nodes": inserted_nodes, "inserted_edges": inserted_edges, "deduplicated_edges": deduplicated_edges, "errors": [], "stats": stats, "limitations": list(_LIMITATIONS)}
    except (OSError, sqlite3.Error, ValueError) as exc:
        if connection is not None:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
        code = str(exc) if str(exc).startswith(("node_identity_conflict:", "edge_identity_conflict:")) else "graph_store_error"
        return _invalid([{"code": code, "detail": type(exc).__name__ if code == "graph_store_error" else "immutable_identity"}], db=resolved_db)
    finally:
        if connection is not None:
            connection.close()


def verify_graph_store(db_path: Path) -> dict[str, Any]:
    """Recompute payload hashes and report corruption without modifying data."""
    resolved_db, path_errors = _validate_db_path(db_path, create_parent=False)
    if path_errors or resolved_db is None or not resolved_db.is_file():
        return _invalid(path_errors or [{"code": "db_missing"}], db=resolved_db)
    connection: sqlite3.Connection | None = None
    errors: list[dict[str, Any]] = []
    try:
        connection = _connect(resolved_db, initialize=False)
        metadata = {row["key"]: row["value"] for row in connection.execute("SELECT key, value FROM graph_metadata")}
        if metadata.get("schema") != SCHEMA:
            errors.append({"code": "store_schema_invalid", "received": metadata.get("schema")})
        for row in connection.execute("SELECT node_id, payload_json, payload_sha256 FROM graph_nodes"):
            try:
                observed = hashlib.sha256(row["payload_json"].encode("utf-8")).hexdigest()
            except UnicodeError:
                observed = None
            if observed != row["payload_sha256"]:
                errors.append({"code": "node_hash_mismatch", "node_id": row["node_id"]})
        for row in connection.execute("SELECT edge_id, payload_json, payload_sha256 FROM graph_edges"):
            try:
                observed = hashlib.sha256(row["payload_json"].encode("utf-8")).hexdigest()
            except UnicodeError:
                observed = None
            if observed != row["payload_sha256"]:
                errors.append({"code": "edge_hash_mismatch", "edge_id": row["edge_id"]})
        stats = _stats(connection)
        return {"schema": SCHEMA, "status": "pass" if not errors else "fail", "db": str(resolved_db), "errors": errors, "stats": stats, "limitations": list(_LIMITATIONS)}
    except (OSError, sqlite3.Error) as exc:
        return _invalid([{"code": "graph_store_error", "detail": type(exc).__name__}], db=resolved_db)
    finally:
        if connection is not None:
            connection.close()


def get_node(db_path: Path, node_id: str) -> dict[str, Any]:
    """Read one immutable node projection, returning explicit not-found state."""
    resolved_db, path_errors = _validate_db_path(db_path, create_parent=False)
    if path_errors or resolved_db is None or not resolved_db.is_file():
        return {"schema": SCHEMA, "status": "invalid", "errors": path_errors or [{"code": "db_missing"}], "node": None, "limitations": list(_LIMITATIONS)}
    if not isinstance(node_id, str) or not node_id.strip():
        return {"schema": SCHEMA, "status": "invalid", "errors": [{"code": "node_id_invalid"}], "node": None, "limitations": list(_LIMITATIONS)}
    connection: sqlite3.Connection | None = None
    try:
        connection = _connect(resolved_db, initialize=False)
        row = connection.execute("SELECT node_id, kind, payload_json, payload_sha256 FROM graph_nodes WHERE node_id = ?", (node_id.strip(),)).fetchone()
        if row is None:
            return {"schema": SCHEMA, "status": "not_found", "node": None, "errors": [], "limitations": list(_LIMITATIONS)}
        try:
            payload = json.loads(row["payload_json"])
        except json.JSONDecodeError:
            return {"schema": SCHEMA, "status": "invalid", "node": None, "errors": [{"code": "node_payload_invalid", "node_id": row["node_id"]}], "limitations": list(_LIMITATIONS)}
        return {"schema": SCHEMA, "status": "complete", "node": payload, "payload_sha256": row["payload_sha256"], "errors": [], "limitations": list(_LIMITATIONS)}
    except (OSError, sqlite3.Error) as exc:
        return {"schema": SCHEMA, "status": "invalid", "node": None, "errors": [{"code": "graph_store_error", "detail": type(exc).__name__}], "limitations": list(_LIMITATIONS)}
    finally:
        if connection is not None:
            connection.close()


def write_graph_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
