"""Tests for PHP and Laravel framework adapter."""

import pytest
from trace_engine.parsing.parser import CodeParser
from trace_engine.framework.php import PHPFrameworkAdapter


def test_laravel_routes_extraction():
    code = """<?php

    use Illuminate\\Support\\Facades\\Route;
    use App\\Http\\Controllers\\OrderController;

    Route::get('/api/v1/orders/{order_id}', [OrderController::class, 'show']);
    Route::post('/api/v1/orders/{order_id}/refund', [OrderController::class, 'refund']);
    """
    parser = CodeParser()
    pf = parser.parse("routes/api.php", code, "php")

    adapter = PHPFrameworkAdapter()
    assert adapter.can_handle(pf) is True

    endpoints = adapter.extract_endpoints(pf, code)
    assert len(endpoints) == 2

    get_ep = next(e for e in endpoints if e.method == "GET")
    assert get_ep.path == "/api/v1/orders/{order_id}"
    assert get_ep.object_identifier is True
    assert any(p.name == "order_id" for p in get_ep.parameters)

    post_ep = next(e for e in endpoints if e.method == "POST")
    assert post_ep.path == "/api/v1/orders/{order_id}/refund"
    assert post_ep.state_changing is True


def test_native_php_script_extraction():
    code = """<?php
    $id = $_GET['record_id'];
    $payload = $_POST['audit_note'];
    $conn = mysqli_connect("localhost", "root", "", "app");
    $result = mysqli_query($conn, "SELECT * FROM records WHERE id = " . $id);
    ?>
    """
    parser = CodeParser()
    pf = parser.parse("public/api/records.php", code, "php")

    adapter = PHPFrameworkAdapter()
    assert adapter.can_handle(pf) is True

    endpoints = adapter.extract_endpoints(pf, code)
    assert len(endpoints) >= 1
    ep = endpoints[0]
    assert ep.database_access is True
    assert any(p.name == "record_id" and p.location == "query" for p in ep.parameters)
    assert any(p.name == "audit_note" and p.location == "body" for p in ep.parameters)
