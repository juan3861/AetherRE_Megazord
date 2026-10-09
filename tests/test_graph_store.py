import json
import sqlite3
from argparse import Namespace

from aether_re.graph_store import get_node, ingest_graph, verify_graph_store, write_graph_report
from megazord import cmd_graph_ingest, cmd_graph_verify, cmd_graph_node


def _graph():
    return {
        "schema": "source-graph.v1",
        "nodes": [
            {"id": "module:main", "kind": "module", "path": "main.py"},
            {"id": "function:main.run", "kind": "function", "module": "main", "line": 1},
        ],
        "edges": [{"kind": "defines", "source": "module:main", "target": "function:main.run", "resolved": True}],
    }


def test_graph_store_ingests_idempotently_and_verifies_hashes(tmp_path):
    db = tmp_path / "graph.sqlite"
    first = ingest_graph(db, _graph(), run_id="run-1")
    second = ingest_graph(db, {"graph": _graph()}, run_id="run-2")
    assert first["status"] == second["status"] == "complete"
    assert first["inserted_nodes"] == 2 and first["inserted_edges"] == 1
    assert second["inserted_nodes"] == second["inserted_edges"] == 0
    assert second["stats"] == {"nodes": 2, "edges": 1}
    verified = verify_graph_store(db)
    assert verified["status"] == "pass"
    assert get_node(db, "module:main")["status"] == "complete"
    assert get_node(db, "missing")["status"] == "not_found"


def test_graph_store_rejects_conflicting_identity_atomically(tmp_path):
    db = tmp_path / "graph.sqlite"
    assert ingest_graph(db, _graph(), run_id="run-1")["status"] == "complete"
    changed = _graph()
    changed["nodes"][0]["path"] = "changed.py"
    rejected = ingest_graph(db, changed, run_id="run-2")
    assert rejected["status"] == "invalid"
    assert rejected["errors"][0]["code"].startswith("node_identity_conflict:")
    assert get_node(db, "module:main")["node"]["path"] == "main.py"


def test_graph_store_rejects_malformed_input_and_budgets_without_coercion(tmp_path):
    db = tmp_path / "graph.sqlite"
    assert ingest_graph(db, _graph(), run_id="")["errors"][0]["code"] == "run_id_invalid"
    assert ingest_graph(db, _graph(), run_id="run", max_nodes=True)["errors"][0]["code"] == "graph_budget_invalid"
    assert ingest_graph(db, {"schema": "wrong", "nodes": [], "edges": []}, run_id="run")["errors"][0]["code"] == "graph_schema_invalid"
    duplicate = _graph()
    duplicate["nodes"].append(dict(duplicate["nodes"][0]))
    assert ingest_graph(db, duplicate, run_id="run")["errors"][0]["code"] == "duplicate_node_id"


def test_graph_store_deduplicates_exact_edges_without_inflating_projection(tmp_path):
    graph = _graph()
    graph["edges"].append(dict(graph["edges"][0]))
    report = ingest_graph(tmp_path / "graph.sqlite", graph, run_id="run")
    assert report["status"] == "complete"
    assert report["inserted_edges"] == 1
    assert report["deduplicated_edges"] == 1
    assert report["stats"]["edges"] == 1


def test_graph_store_verify_detects_payload_tamper_and_missing_db_is_read_only(tmp_path):
    db = tmp_path / "graph.sqlite"
    assert verify_graph_store(db)["errors"][0]["code"] == "db_missing"
    assert not db.exists()
    assert ingest_graph(db, _graph(), run_id="run")["status"] == "complete"
    with sqlite3.connect(db) as connection:
        connection.execute("UPDATE graph_nodes SET payload_json = ? WHERE node_id = ?", ('{"id":"module:main","kind":"module","path":"tampered"}', "module:main"))
        connection.commit()
    report = verify_graph_store(db)
    assert report["status"] == "fail"
    assert any(item["code"] == "node_hash_mismatch" for item in report["errors"])


def test_graph_store_readers_do_not_initialize_invalid_database(tmp_path):
    db = tmp_path / "empty.sqlite"
    db.write_bytes(b"")
    before = db.read_bytes()
    report = get_node(db, "module:main")
    assert report["status"] == "invalid"
    assert db.read_bytes() == before


def test_graph_store_cli_materializes_ingest_verify_and_node(tmp_path):
    source = tmp_path / "graph.json"
    source.write_text(json.dumps(_graph()), encoding="utf-8")
    db = tmp_path / "graph.sqlite"
    out = tmp_path / "ingest.json"
    code = cmd_graph_ingest(Namespace(input=str(source), db=str(db), run_id="cli-run", out=str(out), max_nodes=100, max_edges=100))
    assert code == 0
    assert json.loads(out.read_text(encoding="utf-8"))["status"] == "complete"
    verify_out = tmp_path / "verify.json"
    assert cmd_graph_verify(Namespace(db=str(db), out=str(verify_out))) == 0
    assert json.loads(verify_out.read_text(encoding="utf-8"))["status"] == "pass"
    node_out = tmp_path / "node.json"
    assert cmd_graph_node(Namespace(db=str(db), node_id="module:main", out=str(node_out))) == 0
    assert json.loads(node_out.read_text(encoding="utf-8"))["node"]["id"] == "module:main"


def test_graph_store_writer(tmp_path):
    out = tmp_path / "report.json"
    write_graph_report(ingest_graph(tmp_path / "db.sqlite", _graph(), run_id="run"), out)
    assert json.loads(out.read_text(encoding="utf-8"))["schema"] == "graph-store.v1"
