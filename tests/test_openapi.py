"""OpenAPI ingestion, schema-valid samples, and the spec/code inventory diff."""

import json
from pathlib import Path

import pytest

from trace_engine.framework.base import Endpoint
from trace_engine.framework.openapi import (
    SpecError,
    find_spec,
    load_document,
    merge_with_code,
    parse_spec,
    sample_from_schema,
)
from trace_engine.parsing.locations import SourceLocation

SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "Shop"},
    "servers": [{"url": "http://localhost:8000/api/v1"}],
    "security": [{"bearer": []}],
    "paths": {
        "/health": {"get": {"security": [], "operationId": "health"}},
        "/items": {
            "get": {"operationId": "listItems"},
            "post": {
                "operationId": "createItem",
                "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/NewItem"}}}},
            },
        },
        "/items/{itemId}": {
            "parameters": [{"name": "itemId", "in": "path", "required": True, "schema": {"type": "string"}}],
            "get": {"operationId": "getItem"},
            "delete": {"operationId": "deleteItem"},
        },
        "/fetch": {"post": {"parameters": [{"name": "callback_url", "in": "query", "schema": {"type": "string"}}]}},
    },
    "components": {
        "schemas": {
            "NewItem": {
                "type": "object",
                "required": ["name", "owner"],
                "properties": {
                    "name": {"type": "string", "minLength": 6},
                    "owner": {"type": "string", "format": "email"},
                    "qty": {"type": "integer", "minimum": 2},
                    "tags": {"type": "array", "items": {"type": "string"}},
                    "kind": {"enum": ["a", "b"]},
                },
            }
        }
    },
}


@pytest.fixture
def spec_file(tmp_path: Path) -> Path:
    path = tmp_path / "openapi.json"
    path.write_text(json.dumps(SPEC), encoding="utf-8")
    return path


def test_find_spec_checks_root_and_docs(tmp_path: Path):
    assert find_spec(tmp_path) is None
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "swagger.json").write_text("{}", encoding="utf-8")
    assert find_spec(tmp_path).name == "swagger.json"


def test_parse_spec_builds_endpoints(spec_file: Path, tmp_path: Path):
    info = parse_spec(spec_file, tmp_path)
    by = {f"{e.method} {e.path}": e for e in info.endpoints}
    assert info.title == "Shop" and info.path == "openapi.json"
    assert set(by) == {
        "GET /api/v1/health", "GET /api/v1/items", "POST /api/v1/items",
        "GET /api/v1/items/{itemId}", "DELETE /api/v1/items/{itemId}", "POST /api/v1/fetch",
    }
    assert by["GET /api/v1/health"].auth_required is False, "operation-level security: [] disables auth"
    assert by["GET /api/v1/items"].auth_required is True, "global security applies"
    item = by["GET /api/v1/items/{itemId}"]
    assert item.object_identifier and item.database_access and item.origin == "spec"
    assert item.parameters[0].location == "path" and item.parameters[0].name == "itemId"
    assert by["POST /api/v1/fetch"].external_network is True
    assert by["DELETE /api/v1/items/{itemId}"].state_changing is True


def test_hints_carry_schema_valid_bodies(spec_file: Path, tmp_path: Path):
    hints = parse_spec(spec_file, tmp_path).hints
    body = hints["POST /api/v1/items"]["body"]
    assert body["owner"] == "trace@example.com"
    assert len(body["name"]) >= 6
    assert set(body) == {"name", "owner"}, "only required properties are sent"
    assert hints["DELETE /api/v1/items/{itemId}"]["exists"] is True


def test_sample_from_schema_handles_refs_enums_and_cycles():
    doc = {"components": {"schemas": {"Node": {"type": "object", "properties": {"child": {"$ref": "#/components/schemas/Node"}}}}}}
    out = sample_from_schema(doc, {"$ref": "#/components/schemas/Node"})
    assert isinstance(out, dict)
    assert sample_from_schema({}, {"enum": ["x", "y"]}) == "x"
    assert sample_from_schema({}, {"type": "array", "items": {"type": "integer", "minimum": 5}}) == [5]
    assert sample_from_schema({}, {"allOf": [{"type": "object", "properties": {"a": {"type": "boolean"}}}]}) == {"a": True}
    assert sample_from_schema({}, {"$ref": "#/nope"}) is None


def test_invalid_documents_are_reported(tmp_path: Path):
    bad = tmp_path / "openapi.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(SpecError):
        load_document(bad)
    bad.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
    with pytest.raises(SpecError):
        load_document(bad)


def ep(method, path, auth=False, origin="code"):
    return Endpoint(
        id=f"ep_{method}_{path}", method=method, path=path, handler_name="h", auth_required=auth,
        source=SourceLocation(file="app.py", line_start=1, line_end=1), origin=origin,
    )


def test_merge_reports_inventory_and_adds_spec_only_routes():
    code = [ep("GET", "/api/v1/items/{id}"), ep("POST", "/internal/debug")]
    spec = [
        ep("GET", "/items/{itemId}", auth=True, origin="spec"),
        ep("DELETE", "/items/{itemId}", origin="spec"),
    ]
    merged, inv = merge_with_code(code, spec)
    assert inv["matched"] == ["1"]
    assert inv["documented_not_in_code"] == ["DELETE /items/{itemId}"]
    assert inv["in_code_not_documented"] == ["POST /internal/debug"]
    assert inv["auth_mismatch"] and "GET /items/{itemId}" in inv["auth_mismatch"][0]
    assert [e.path for e in merged if e.origin == "spec"] == ["/items/{itemId}"]
    assert len(merged) == 3
