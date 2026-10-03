"""Serialization and SQLite persistence for Attack-Path Model."""

import sqlite3
import json
from pathlib import Path
from typing import Optional
from trace_engine.apm.model import AttackPathModel
from trace_engine.apm.nodes import APMNode, NodeType
from trace_engine.apm.edges import APMEdge, EdgeType
from trace_engine.parsing.locations import SourceLocation


def save_apm_sqlite(apm: AttackPathModel, db_path: Path) -> None:
    """Save APM graph to SQLite database."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS apm_nodes (
            id TEXT PRIMARY KEY,
            node_type TEXT NOT NULL,
            label TEXT NOT NULL,
            file TEXT,
            line_start INTEGER,
            line_end INTEGER,
            properties TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS apm_edges (
            source_id TEXT NOT NULL,
            target_id TEXT NOT NULL,
            edge_type TEXT NOT NULL,
            properties TEXT
        )
    """)

    cursor.execute("DELETE FROM apm_nodes")
    cursor.execute("DELETE FROM apm_edges")

    for node in apm.nodes_data.values():
        cursor.execute(
            """
            INSERT INTO apm_nodes (id, node_type, label, file, line_start, line_end, properties)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                node.id,
                node.node_type.value,
                node.label,
                node.location.file if node.location else None,
                node.location.line_start if node.location else None,
                node.location.line_end if node.location else None,
                json.dumps(node.properties),
            ),
        )

    for edge in apm.edges_data:
        cursor.execute(
            """
            INSERT INTO apm_edges (source_id, target_id, edge_type, properties)
            VALUES (?, ?, ?, ?)
            """,
            (
                edge.source_id,
                edge.target_id,
                edge.edge_type.value,
                json.dumps(edge.properties),
            ),
        )

    conn.commit()
    conn.close()


def export_apm_json(apm: AttackPathModel, json_path: Path) -> None:
    """Export APM graph to JSON."""
    json_path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "name": apm.name,
        "nodes": [
            {
                "id": n.id,
                "node_type": n.node_type.value,
                "label": n.label,
                "location": n.location.model_dump() if n.location else None,
                "properties": n.properties,
            }
            for n in apm.nodes_data.values()
        ],
        "edges": [
            {
                "source": e.source_id,
                "target": e.target_id,
                "edge_type": e.edge_type.value,
                "properties": e.properties,
            }
            for e in apm.edges_data
        ],
        "summary": apm.summary(),
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
