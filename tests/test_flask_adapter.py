"""Tests for Flask framework adapter."""

import pytest
from trace_engine.parsing.parser import CodeParser
from trace_engine.framework.flask import FlaskFrameworkAdapter


def test_flask_routes_and_parameters():
    code = """
    from flask import Flask, request, jsonify

    app = Flask(__name__)

    @app.route('/api/v1/users/<int:user_id>', methods=['GET'])
    def get_user_profile(user_id):
        include_details = request.args.get('details')
        # Vulnerable SQL execution
        user = db.session.execute(f"SELECT * FROM users WHERE id = {user_id}")
        return jsonify({"id": user_id})

    @app.route('/api/v1/data/export', methods=['POST'])
    def export_data():
        dest_url = request.json.get('callback_url')
        res = requests.post(dest_url, json={"exported": True})
        return jsonify({"status": "exported"})
    """
    parser = CodeParser()
    pf = parser.parse("app.py", code, "python")

    adapter = FlaskFrameworkAdapter()
    assert adapter.can_handle(pf) is True

    endpoints = adapter.extract_endpoints(pf, code)
    assert len(endpoints) == 2

    # Check GET /api/v1/users/{user_id}
    get_ep = next(e for e in endpoints if e.method == "GET")
    assert get_ep.path == "/api/v1/users/{user_id}"
    assert get_ep.object_identifier is True
    assert get_ep.database_access is True
    assert any(p.name == "user_id" and p.location == "path" for p in get_ep.parameters)
    assert any(p.name == "details" and p.location == "query" for p in get_ep.parameters)

    # Check POST /api/v1/data/export
    post_ep = next(e for e in endpoints if e.method == "POST")
    assert post_ep.path == "/api/v1/data/export"
    assert post_ep.state_changing is True
    assert post_ep.external_network is True
    assert any(p.name == "callback_url" and p.location == "body" for p in post_ep.parameters)
