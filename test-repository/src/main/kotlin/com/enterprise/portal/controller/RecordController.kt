package com.enterprise.portal.controller

import org.springframework.web.bind.annotation.*
import org.springframework.http.ResponseEntity
import com.enterprise.portal.service.AuditService

@RestController
@RequestMapping("/api/v2/records")
class RecordController(private val auditService: AuditService) {

    /**
     * BOLA: Broken Object-Level Authorization in Kotlin Spring Boot.
     * Direct database lookup by primary key without verifying tenant identity.
     */
    @GetMapping("/{recordId}")
    fun getRecordById(
        @PathVariable recordId: String,
        @RequestHeader(value = "X-Tenant-ID", required = false) tenantId: String?
    ): ResponseEntity<Any> {
        val record = auditService.findRecordById(recordId)
        return if (record != null) {
            ResponseEntity.ok(record)
        } else {
            ResponseEntity.notFound().build()
        }
    }

    /**
     * SSRF: Server-Side Request Forgery in Kotlin Spring Boot.
     * Uses RestTemplate to forward audit metrics to arbitrary callback URL.
     */
    @PostMapping("/export/dispatch")
    fun dispatchAuditExport(@RequestBody payload: Map<String, String>): ResponseEntity<Any> {
        val callbackUrl = payload["callbackUrl"] ?: return ResponseEntity.badRequest().body(mapOf("error" to "Missing callbackUrl"))
        // [TRACE HARNESS FIX: Egress filtering against SSRF]
        if (callbackUrl.contains("localhost") || callbackUrl.contains("127.0.0.1") || callbackUrl.contains("internal") || callbackUrl.contains("169.254")) {
            return ResponseEntity.status(403).body(mapOf("error" to "SSRF blocked: outbound internal destination rejected"))
        }
        val result = auditService.dispatchOutboundAudit(callbackUrl)
        return ResponseEntity.ok(result)
    }
}
