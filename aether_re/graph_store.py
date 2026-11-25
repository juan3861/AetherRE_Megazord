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


# ---------------------------------------------------------------------------
# Pillar 1 (v9.0): Persistent SQLite WAL Binary Knowledge Store (50k+ Fns)
# ---------------------------------------------------------------------------

class BinaryKnowledgeStore:
    """High-throughput incremental SQLite WAL graph store for multi-megabyte binaries.

    Stores per-binary CFG functions, xrefs, recovered types/structs, and
    content-addressed IR/C decompilation cache without altering existing
    `graph-store.v1` report behavior.
    """

    def __init__(self, db_path: str | Path) -> None:
        resolved, errs = _validate_db_path(Path(db_path), create_parent=True)
        if errs or resolved is None:
            raise ValueError(f"Invalid knowledge store path: {errs}")
        self.db_path = resolved
        self._init_schema()

    def _open(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self) -> None:
        conn = self._open()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS bk_binaries (
                    binary_sha256 TEXT PRIMARY KEY,
                    source_path TEXT NOT NULL,
                    project_kind TEXT NOT NULL,
                    architecture TEXT NOT NULL,
                    function_count INTEGER NOT NULL DEFAULT 0,
                    overall_congruence_pct REAL NOT NULL DEFAULT 0.0,
                    metadata_json TEXT NOT NULL,
                    updated_at REAL NOT NULL DEFAULT (unixepoch('now'))
                );
                CREATE TABLE IF NOT EXISTS bk_functions (
                    binary_sha256 TEXT NOT NULL,
                    rva INTEGER NOT NULL,
                    fn_name TEXT NOT NULL,
                    c_ident TEXT NOT NULL,
                    ordinal INTEGER NOT NULL DEFAULT 0,
                    is_exported INTEGER NOT NULL DEFAULT 0,
                    own_lifted INTEGER NOT NULL DEFAULT 0,
                    code_sha256 TEXT NOT NULL DEFAULT '',
                    prototype_json TEXT NOT NULL DEFAULT '{}',
                    c_code TEXT NOT NULL DEFAULT '',
                    typed_c_code TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY (binary_sha256, rva)
                );
                CREATE INDEX IF NOT EXISTS idx_bk_fn_name ON bk_functions(binary_sha256, fn_name);
                CREATE TABLE IF NOT EXISTS bk_xrefs (
                    binary_sha256 TEXT NOT NULL,
                    src_rva INTEGER NOT NULL,
                    dst_rva INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    site_rva INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (binary_sha256, src_rva, dst_rva, kind, site_rva)
                );
                CREATE INDEX IF NOT EXISTS idx_bk_xrefs_dst ON bk_xrefs(binary_sha256, dst_rva);
                CREATE TABLE IF NOT EXISTS bk_types (
                    binary_sha256 TEXT NOT NULL,
                    type_name TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL DEFAULT 0,
                    source TEXT NOT NULL DEFAULT 'inferred',
                    fields_json TEXT NOT NULL DEFAULT '{}',
                    PRIMARY KEY (binary_sha256, type_name)
                );
                CREATE TABLE IF NOT EXISTS bk_ir_cache (
                    code_sha256 TEXT PRIMARY KEY,
                    arch TEXT NOT NULL,
                    lifted_c TEXT NOT NULL,
                    structured_c TEXT NOT NULL DEFAULT '',
                    llvm_ir TEXT NOT NULL DEFAULT ''
                );
                """
            )
            conn.commit()
        finally:
            conn.close()

    def upsert_binary(
        self,
        binary_sha256: str,
        *,
        source_path: str,
        project_kind: str,
        architecture: str,
        function_count: int = 0,
        overall_congruence_pct: float = 0.0,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        conn = self._open()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO bk_binaries(
                        binary_sha256, source_path, project_kind, architecture,
                        function_count, overall_congruence_pct, metadata_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(binary_sha256) DO UPDATE SET
                        source_path=excluded.source_path,
                        project_kind=excluded.project_kind,
                        architecture=excluded.architecture,
                        function_count=excluded.function_count,
                        overall_congruence_pct=excluded.overall_congruence_pct,
                        metadata_json=excluded.metadata_json,
                        updated_at=unixepoch('now')
                    """,
                    (
                        binary_sha256,
                        source_path,
                        project_kind,
                        architecture,
                        int(function_count),
                        float(overall_congruence_pct),
                        _canonical(metadata or {}),
                    ),
                )
        finally:
            conn.close()

    def upsert_functions_batch(self, binary_sha256: str, records: list[dict[str, Any]]) -> int:
        if not records:
            return 0
        rows = []
        for rec in records:
            raw_bytes = rec.get("code_slice", b"")
            c_sha = (
                hashlib.sha256(raw_bytes).hexdigest()
                if isinstance(raw_bytes, (bytes, bytearray)) and raw_bytes
                else str(rec.get("code_sha256", ""))
            )
            rows.append(
                (
                    binary_sha256,
                    int(rec.get("rva", 0)),
                    str(rec.get("fn_name", "")),
                    str(rec.get("c_ident", "")),
                    int(rec.get("ordinal", 0)),
                    1 if rec.get("is_exported") else 0,
                    1 if rec.get("own_lifted") else 0,
                    c_sha,
                    _canonical(rec.get("prototype", {})),
                    str(rec.get("c_code", "")),
                    str(rec.get("typed_c_code", "")),
                )
            )
        conn = self._open()
        try:
            with conn:
                conn.executemany(
                    """
                    INSERT INTO bk_functions(
                        binary_sha256, rva, fn_name, c_ident, ordinal, is_exported,
                        own_lifted, code_sha256, prototype_json, c_code, typed_c_code
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(binary_sha256, rva) DO UPDATE SET
                        fn_name=excluded.fn_name,
                        c_ident=excluded.c_ident,
                        ordinal=excluded.ordinal,
                        is_exported=excluded.is_exported,
                        own_lifted=excluded.own_lifted,
                        code_sha256=excluded.code_sha256,
                        prototype_json=excluded.prototype_json,
                        c_code=excluded.c_code,
                        typed_c_code=excluded.typed_c_code
                    """,
                    rows,
                )
            return len(rows)
        finally:
            conn.close()

    def upsert_xrefs_batch(self, binary_sha256: str, xrefs: list[tuple[int, int, str, int]]) -> int:
        if not xrefs:
            return 0
        rows = [(binary_sha256, int(s), int(d), str(k), int(site)) for (s, d, k, site) in xrefs]
        conn = self._open()
        try:
            with conn:
                conn.executemany(
                    "INSERT OR IGNORE INTO bk_xrefs(binary_sha256, src_rva, dst_rva, kind, site_rva) VALUES (?, ?, ?, ?, ?)",
                    rows,
                )
            return len(rows)
        finally:
            conn.close()

    def upsert_types_batch(self, binary_sha256: str, types_list: list[dict[str, Any]]) -> int:
        if not types_list:
            return 0
        rows = [
            (
                binary_sha256,
                str(t.get("name", "")),
                str(t.get("kind", "struct")),
                int(t.get("size_bytes", 0)),
                str(t.get("source", "inferred")),
                _canonical(t.get("fields", {})),
            )
            for t in types_list
            if t.get("name")
        ]
        if not rows:
            return 0
        conn = self._open()
        try:
            with conn:
                conn.executemany(
                    """
                    INSERT INTO bk_types(binary_sha256, type_name, kind, size_bytes, source, fields_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(binary_sha256, type_name) DO UPDATE SET
                        kind=excluded.kind,
                        size_bytes=excluded.size_bytes,
                        source=excluded.source,
                        fields_json=excluded.fields_json
                    """,
                    rows,
                )
            return len(rows)
        finally:
            conn.close()

    def put_ir_cache(self, code_sha256: str, *, arch: str, lifted_c: str, structured_c: str = "", llvm_ir: str = "") -> None:
        if not code_sha256:
            return
        conn = self._open()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO bk_ir_cache(code_sha256, arch, lifted_c, structured_c, llvm_ir)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(code_sha256) DO UPDATE SET
                        arch=excluded.arch,
                        lifted_c=excluded.lifted_c,
                        structured_c=CASE WHEN excluded.structured_c != '' THEN excluded.structured_c ELSE bk_ir_cache.structured_c END,
                        llvm_ir=CASE WHEN excluded.llvm_ir != '' THEN excluded.llvm_ir ELSE bk_ir_cache.llvm_ir END
                    """,
                    (code_sha256, arch, lifted_c, structured_c, llvm_ir),
                )
        finally:
            conn.close()

    def get_ir_cache(self, code_sha256: str) -> dict[str, Any] | None:
        conn = self._open()
        try:
            row = conn.execute(
                "SELECT code_sha256, arch, lifted_c, structured_c, llvm_ir FROM bk_ir_cache WHERE code_sha256 = ?",
                (code_sha256,),
            ).fetchone()
            return dict(row) if row is not None else None
        finally:
            conn.close()

    def query_functions(
        self,
        binary_sha256: str,
        *,
        name_like: str | None = None,
        only_exported: bool = False,
        limit: int = 1000,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        clauses = ["binary_sha256 = ?"]
        params: list[Any] = [binary_sha256]
        if only_exported:
            clauses.append("is_exported = 1")
        if name_like:
            clauses.append("(fn_name LIKE ? OR c_ident LIKE ?)")
            pat = f"%{name_like}%"
            params.extend([pat, pat])
        params.extend([int(limit), int(offset)])
        conn = self._open()
        try:
            rows = conn.execute(
                f"SELECT rva, fn_name, c_ident, ordinal, is_exported, own_lifted, code_sha256, prototype_json, c_code, typed_c_code "
                f"FROM bk_functions WHERE {' AND '.join(clauses)} ORDER BY rva ASC LIMIT ? OFFSET ?",
                params,
            ).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["prototype"] = json.loads(d.pop("prototype_json") or "{}")
                out.append(d)
            return out
        finally:
            conn.close()

    def query_callers(self, binary_sha256: str, dst_rva: int) -> list[dict[str, Any]]:
        conn = self._open()
        try:
            rows = conn.execute(
                """
                SELECT x.src_rva, x.kind, x.site_rva, f.fn_name, f.c_ident
                FROM bk_xrefs x
                LEFT JOIN bk_functions f ON f.binary_sha256 = x.binary_sha256 AND f.rva = x.src_rva
                WHERE x.binary_sha256 = ? AND x.dst_rva = ?
                ORDER BY x.src_rva ASC
                """,
                (binary_sha256, int(dst_rva)),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_binary_summary(self, binary_sha256: str) -> dict[str, Any] | None:
        conn = self._open()
        try:
            b = conn.execute("SELECT * FROM bk_binaries WHERE binary_sha256 = ?", (binary_sha256,)).fetchone()
            if b is None:
                return None
            fn_cnt = int(conn.execute("SELECT COUNT(*) FROM bk_functions WHERE binary_sha256 = ?", (binary_sha256,)).fetchone()[0])
            xr_cnt = int(conn.execute("SELECT COUNT(*) FROM bk_xrefs WHERE binary_sha256 = ?", (binary_sha256,)).fetchone()[0])
            ty_cnt = int(conn.execute("SELECT COUNT(*) FROM bk_types WHERE binary_sha256 = ?", (binary_sha256,)).fetchone()[0])
            d = dict(b)
            d["metadata"] = json.loads(d.pop("metadata_json") or "{}")
            d["stored_functions"] = fn_cnt
            d["stored_xrefs"] = xr_cnt
            d["stored_types"] = ty_cnt
            return d
        finally:
            conn.close()
