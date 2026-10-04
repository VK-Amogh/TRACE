package com.enterprise.portal.controller

import org.springframework.web.bind.annotation.*
import org.springframework.http.ResponseEntity

@RestController
@RequestMapping("/api/v3/patients")
class RecordsController {

    // BOLA / IDOR in patient record download
    @GetMapping("/{patientId}/records/export")
    fun exportPatientRecords(@PathVariable patientId: String): ResponseEntity<Map<String, Any>> {
        // Vulnerable: Directly queries database by patientId without asserting caller's organization or doctor association
        val data = mapOf(
            "patientId" to patientId,
            "medicalHistory" to "Restricted diagnostic charts and genomic markers",
            "confidential" to true
        )
        return ResponseEntity.ok(data)
    }
}
