"""Unit tests for React Router and Next.js framework adapters."""

import pytest
from trace_engine.parsing.parser import CodeParser
from trace_engine.framework.react_router import ReactRouterFrameworkAdapter
from trace_engine.framework.nextjs import NextJSFrameworkAdapter


def test_react_router_loader_action_and_sinks():
    code = """
    import { getProjectByIdFromDB } from "../services/projects.server";
    import { getSessionUser } from "../lib/supabase.server";
    import { requireAdmin } from "../services/admin.server";

    export async function loader({ request, params }: Route.LoaderArgs) {
        const user = await getSessionUser(request);
        const project = await getProjectByIdFromDB(params.id);
        return Response.json({ project });
    }

    export async function action({ request }: Route.ActionArgs) {
        await requireAdmin(request);
        const data = await request.json();
        return Response.json({ success: true });
    }
    """
    parser = CodeParser()
    pf = parser.parse("app/routes/projects.$id.tsx", code, "typescript")

    adapter = ReactRouterFrameworkAdapter()
    assert adapter.can_handle(pf) is True

    endpoints = adapter.extract_endpoints(pf, code)
    assert len(endpoints) == 2

    # GET endpoint from loader
    get_ep = next(e for e in endpoints if e.method == "GET")
    assert get_ep.path == "/projects/{id}"
    assert get_ep.handler_name == "loader"
    assert get_ep.auth_required is True
    assert get_ep.database_access is True
    assert get_ep.object_identifier is True
    assert get_ep.state_changing is False
    assert any(p.name == "id" and p.location == "path" for p in get_ep.parameters)

    # POST endpoint from action
    post_ep = next(e for e in endpoints if e.method == "POST")
    assert post_ep.path == "/projects/{id}"
    assert post_ep.handler_name == "action"
    assert post_ep.auth_required is True
    assert "admin" in post_ep.roles
    assert post_ep.state_changing is True


def test_react_router_flat_routes_and_search_params():
    code = """
    export async function loader({ request }: { request: Request }) {
        const url = new URL(request.url);
        const username = url.searchParams.get("username");
        return Response.json({ available: true, username });
    }
    """
    parser = CodeParser()
    pf = parser.parse("app/routes/api.check-username.ts", code, "typescript")

    adapter = ReactRouterFrameworkAdapter()
    assert adapter.can_handle(pf) is True

    endpoints = adapter.extract_endpoints(pf, code)
    assert len(endpoints) == 1
    ep = endpoints[0]
    assert ep.method == "GET"
    assert ep.path == "/api/check-username"
    assert any(p.name == "username" and p.location == "query" for p in ep.parameters)


def test_nextjs_app_router_route():
    code = """
    import { NextResponse } from "next/server";
    import prisma from "@/lib/prisma";

    export async function GET(request: Request, { params }: { params: { id: string } }) {
        const user = await prisma.user.findUnique({ where: { id: params.id } });
        return NextResponse.json(user);
    }

    export async function DELETE(request: Request, { params }: { params: { id: string } }) {
        await prisma.user.delete({ where: { id: params.id } });
        return NextResponse.json({ ok: true });
    }
    """
    parser = CodeParser()
    pf = parser.parse("app/api/users/[id]/route.ts", code, "typescript")

    adapter = NextJSFrameworkAdapter()
    assert adapter.can_handle(pf) is True

    endpoints = adapter.extract_endpoints(pf, code)
    assert len(endpoints) == 2

    methods = {e.method: e for e in endpoints}
    assert "GET" in methods
    assert "DELETE" in methods

    get_ep = methods["GET"]
    assert get_ep.path == "/api/users/{id}"
    assert get_ep.database_access is True
    assert get_ep.object_identifier is True
    assert any(p.name == "id" and p.location == "path" for p in get_ep.parameters)

    del_ep = methods["DELETE"]
    assert del_ep.path == "/api/users/{id}"
    assert del_ep.state_changing is True


def test_nextjs_pages_router_api():
    code = """
    import type { NextApiRequest, NextApiResponse } from 'next';

    export default async function handler(req: NextApiRequest, res: NextApiResponse) {
        if (req.method === 'POST') {
            return res.status(200).json({ created: true });
        }
        res.status(200).json({ status: 'ok' });
    }
    """
    parser = CodeParser()
    pf = parser.parse("pages/api/posts/[slug].ts", code, "typescript")

    adapter = NextJSFrameworkAdapter()
    assert adapter.can_handle(pf) is True

    endpoints = adapter.extract_endpoints(pf, code)
    assert len(endpoints) >= 1
    assert any(e.path == "/api/posts/{slug}" for e in endpoints)
    assert any(p.name == "slug" for e in endpoints for p in e.parameters)


def test_dart_shelf_router():
    from trace_engine.framework.dart import DartFrameworkAdapter

    code = """
    import 'package:shelf/shelf.dart';
    import 'package:shelf_router/shelf_router.dart';

    Response _getProject(Request request, String id) {
        return Response.ok('{"id": "$id"}');
    }

    Response _refundPayment(Request request) {
        return Response.ok('{"status": "refunded"}');
    }

    Router getRouter() {
        final router = Router();
        router.get('/api/v1/projects/<id>', _getProject);
        router.post('/api/v1/billing/refund', _refundPayment);
        return router;
    }
    """
    parser = CodeParser()
    pf = parser.parse("lib/routes.dart", code, "dart")

    adapter = DartFrameworkAdapter()
    assert adapter.can_handle(pf) is True

    endpoints = adapter.extract_endpoints(pf, code)
    assert len(endpoints) == 2

    get_ep = next(e for e in endpoints if e.method == "GET")
    assert get_ep.path == "/api/v1/projects/{id}"
    assert get_ep.object_identifier is True
    assert any(p.name == "id" for p in get_ep.parameters)

    post_ep = next(e for e in endpoints if e.method == "POST")
    assert post_ep.path == "/api/v1/billing/refund"
    assert post_ep.state_changing is True


def test_springboot_java_and_kotlin():
    from trace_engine.framework.springboot import SpringBootFrameworkAdapter

    code = """
    package com.enterprise.portal.controller;

    import org.springframework.web.bind.annotation.*;
    import org.springframework.security.access.prepost.PreAuthorize;

    @RestController
    @RequestMapping("/api/v2/patients")
    public class PatientController {

        @GetMapping("/{patientId}/records/{recordId}")
        public ResponseEntity<?> getRecord(
            @PathVariable Long patientId,
            @PathVariable Long recordId
        ) {
            return ResponseEntity.ok(patientRepository.findById(recordId));
        }

        @PreAuthorize("hasRole('ADMIN')")
        @PostMapping("/admin/purge")
        public ResponseEntity<?> purgeRecords() {
            return ResponseEntity.ok("purged");
        }
    }
    """
    parser = CodeParser()
    pf = parser.parse("src/main/java/com/enterprise/portal/controller/PatientController.java", code, "java")

    adapter = SpringBootFrameworkAdapter()
    assert adapter.can_handle(pf) is True

    endpoints = adapter.extract_endpoints(pf, code)
    assert len(endpoints) == 2

    get_ep = next(e for e in endpoints if e.method == "GET")
    assert get_ep.path == "/api/v2/patients/{patientId}/records/{recordId}"
    assert get_ep.object_identifier is True
    assert get_ep.database_access is True
    assert any(p.name == "patientId" for p in get_ep.parameters)
    assert any(p.name == "recordId" for p in get_ep.parameters)

    post_ep = next(e for e in endpoints if e.method == "POST")
    assert post_ep.path == "/api/v2/patients/admin/purge"
    assert post_ep.auth_required is True
    assert "admin" in post_ep.roles


def test_go_gin_adapter():
    from trace_engine.framework.go import GoFrameworkAdapter

    code = """
    package main

    import (
        "github.com/gin-gonic/gin"
        "net/http"
    )

    func SetupRouter() *gin.Engine {
        r := gin.Default()
        r.GET("/api/v1/users/:userId", func(c *gin.Context) {
            c.JSON(http.StatusOK, gin.H{"status": "ok"})
        })
        r.POST("/api/v1/users/:userId/role", func(c *gin.Context) {
            c.JSON(http.StatusOK, gin.H{"promoted": true})
        })
        return r
    }
    """
    parser = CodeParser()
    pf = parser.parse("main.go", code, "go")

    adapter = GoFrameworkAdapter()
    assert adapter.can_handle(pf) is True

    endpoints = adapter.extract_endpoints(pf, code)
    assert len(endpoints) == 2
    assert any(e.path == "/api/v1/users/{userId}" and e.method == "GET" for e in endpoints)
    assert any(e.path == "/api/v1/users/{userId}/role" and e.method == "POST" for e in endpoints)


def test_ruby_rails_adapter():
    from trace_engine.framework.ruby import RubyFrameworkAdapter

    code = """
    Rails.application.routes.draw do
      get '/api/v1/customers/:id', to: 'customers#show'
      post '/api/v1/customers', to: 'customers#create'
    end
    """
    parser = CodeParser()
    pf = parser.parse("config/routes.rb", code, "ruby")

    adapter = RubyFrameworkAdapter()
    assert adapter.can_handle(pf) is True

    endpoints = adapter.extract_endpoints(pf, code)
    assert len(endpoints) == 2
    assert any(e.path == "/api/v1/customers/{id}" and e.method == "GET" for e in endpoints)
    assert any(e.path == "/api/v1/customers" and e.method == "POST" for e in endpoints)


def test_rust_actix_and_axum_adapter():
    from trace_engine.framework.rust import RustFrameworkAdapter

    code = """
    #[get("/api/v1/items/{item_id}")]
    pub async fn get_item(path: web::Path<String>) -> impl Responder {
        HttpResponse::Ok().body("item")
    }

    fn app() -> Router {
        Router::new().route("/api/v1/orders", post(create_order))
    }
    """
    parser = CodeParser()
    pf = parser.parse("src/main.rs", code, "rust")

    adapter = RustFrameworkAdapter()
    assert adapter.can_handle(pf) is True

    endpoints = adapter.extract_endpoints(pf, code)
    assert len(endpoints) == 2
    assert any(e.path == "/api/v1/items/{item_id}" and e.method == "GET" for e in endpoints)
    assert any(e.path == "/api/v1/orders" and e.method == "POST" for e in endpoints)


def test_csharp_aspnet_adapter():
    from trace_engine.framework.csharp import CSharpFrameworkAdapter

    code = """
    [Route("api/[controller]")]
    [ApiController]
    public class InvoicesController : ControllerBase
    {
        [HttpGet("{invoiceId}")]
        public async Task<IActionResult> GetInvoice(string invoiceId)
        {
            return Ok();
        }

        [HttpPost("refund")]
        public async Task<IActionResult> Refund()
        {
            return Ok();
        }
    }
    """
    parser = CodeParser()
    pf = parser.parse("Controllers/InvoicesController.cs", code, "csharp")

    adapter = CSharpFrameworkAdapter()
    assert adapter.can_handle(pf) is True

    endpoints = adapter.extract_endpoints(pf, code)
    assert len(endpoints) == 2
    assert any("invoiceId" in e.path and e.method == "GET" for e in endpoints)
    assert any("refund" in e.path and e.method == "POST" for e in endpoints)

