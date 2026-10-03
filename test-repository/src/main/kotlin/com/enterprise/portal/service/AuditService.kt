package com.enterprise.portal.service

import org.springframework.stereotype.Service
import org.springframework.web.client.RestTemplate

@Service
class AuditService {
    private val restTemplate = RestTemplate()

    fun findRecordById(recordId: String): Map<String, Any>? {
        // Simulates database repository findById
        return mapOf(
            "recordId" to recordId,
            "tenantId" to "tenant-enterprise-99",
            "sensitivity" to "CONFIDENTIAL",
            "payload" to "Cryptographic audit trail: sha256:d8a94b291c89f..."
        )
    }

    fun dispatchOutboundAudit(callbackUrl: String): Map<String, Any> {
        // SINK: Outbound network request to arbitrary callback without IP filtering
        val response = restTemplate.getForObject(callbackUrl, String::class.java)
        return mapOf(
            "status" to "dispatched",
            "target" to callbackUrl,
            "responseSnippet" to (response?.take(200) ?: "empty")
        )
    }
}
