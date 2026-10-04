# TRACE Security Assessment Report — test-repository
Threat Reconnaissance & Attack-path Correlation Engine

## Summary
- Total Correlated Findings: **18**

| ID | Severity | Confidence | Category | Endpoint | Title |
|---|---|---|---|---|---|
| TR-BFLA-001 | HIGH | MEDIUM | BFLA | `GET /api/v1/organizations/{orgId}/projects/{projectId}` | Potential BFLA on privileged endpoint GET /api/v1/organizations/{orgId}/projects/{projectId} |
| TR-CORS-002 | MEDIUM | MEDIUM | CORS | `GET /api/v1/organizations/{orgId}/projects/{projectId}` | Potential CORS Misconfiguration on GET /api/v1/organizations/{orgId}/projects/{projectId} |
| TR-BFLA-003 | HIGH | MEDIUM | BFLA | `POST /api/v1/admin/users/{userId}/role` | Potential BFLA on privileged endpoint POST /api/v1/admin/users/{userId}/role |
| TR-MASS-004 | MEDIUM | MEDIUM | MASS_ASSIGNMENT | `POST /api/v1/admin/users/{userId}/role` | Potential Mass Assignment on POST /api/v1/admin/users/{userId}/role |
| TR-CORS-005 | MEDIUM | MEDIUM | CORS | `POST /api/v1/admin/users/{userId}/role` | Potential CORS Misconfiguration on POST /api/v1/admin/users/{userId}/role |
| TR-BFLA-006 | HIGH | MEDIUM | BFLA | `POST /api/v1/integrations/webhooks/preview` | Potential BFLA on privileged endpoint POST /api/v1/integrations/webhooks/preview |
| TR-SSTI-007 | CRITICAL | MEDIUM | SSTI | `POST /api/v1/integrations/webhooks/preview` | Potential Template Injection on POST /api/v1/integrations/webhooks/preview |
| TR-CORS-008 | MEDIUM | MEDIUM | CORS | `POST /api/v1/integrations/webhooks/preview` | Potential CORS Misconfiguration on POST /api/v1/integrations/webhooks/preview |
| TR-BFLA-009 | HIGH | MEDIUM | BFLA | `POST /api/v1/billing/invoices/{invoiceId}/refund` | Potential BFLA on privileged endpoint POST /api/v1/billing/invoices/{invoiceId}/refund |
| TR-CORS-010 | MEDIUM | MEDIUM | CORS | `POST /api/v1/billing/invoices/{invoiceId}/refund` | Potential CORS Misconfiguration on POST /api/v1/billing/invoices/{invoiceId}/refund |
| TR-BFLA-011 | HIGH | MEDIUM | BFLA | `PUT /api/v1/users/profile` | Potential BFLA on privileged endpoint PUT /api/v1/users/profile |
| TR-MASS-012 | MEDIUM | MEDIUM | MASS_ASSIGNMENT | `PUT /api/v1/users/profile` | Potential Mass Assignment on PUT /api/v1/users/profile |
| TR-TRAV-013 | HIGH | MEDIUM | PATH_TRAVERSAL | `PUT /api/v1/users/profile` | Potential Path Traversal on PUT /api/v1/users/profile |
| TR-CORS-014 | MEDIUM | MEDIUM | CORS | `PUT /api/v1/users/profile` | Potential CORS Misconfiguration on PUT /api/v1/users/profile |
| TR-AUTH-015 | CRITICAL | HIGH | AUTHENTICATION | `GET /api/v2/records/{recordId}` | Unauthenticated sensitive endpoint GET /api/v2/records/{recordId} |
| TR-SSRF-016 | HIGH | HIGH | SSRF | `GET /api/v2/records/{recordId}` | Potential SSRF on GET /api/v2/records/{recordId} |
| TR-AUTH-017 | CRITICAL | HIGH | AUTHENTICATION | `POST /api/v2/records/export/dispatch` | Unauthenticated sensitive endpoint POST /api/v2/records/export/dispatch |
| TR-SSRF-018 | HIGH | HIGH | SSRF | `POST /api/v2/records/export/dispatch` | Potential SSRF on POST /api/v2/records/export/dispatch |

---

## Finding Details

### [TR-BFLA-001] Potential BFLA on privileged endpoint GET /api/v1/organizations/{orgId}/projects/{projectId}
- **Category:** BFLA
- **Severity:** HIGH
- **Confidence:** MEDIUM
- **Endpoint:** `GET /api/v1/organizations/{orgId}/projects/{projectId}`
- **Source:** `lib/api/routes.dart:14`

#### Attack Path Hops
1. `ep_dart_lib_api_routes_dart_14_GET`
1. `fn_lib_controllers_organization_controller_dart_getOrganizationProject`

#### Static AST Evidence
- Privileged path/role identifier present: ['admin']
- Source location: lib/api/routes.dart:14

#### Remediation Guidance
Implement declarative role-based access control (RBAC) middleware. Validate user privileges on the backend for every privileged/administrative route.

---

### [TR-CORS-002] Potential CORS Misconfiguration on GET /api/v1/organizations/{orgId}/projects/{projectId}
- **Category:** CORS
- **Severity:** MEDIUM
- **Confidence:** MEDIUM
- **Endpoint:** `GET /api/v1/organizations/{orgId}/projects/{projectId}`
- **Source:** `lib/api/routes.dart:14`

#### Attack Path Hops
1. `ep_dart_lib_api_routes_dart_14_GET`
1. `fn_lib_controllers_organization_controller_dart_getOrganizationProject`

#### Static AST Evidence
- Authenticated: True, Sensitive data: True

#### Remediation Guidance
Review access control and input validation on this attack path.

---

### [TR-BFLA-003] Potential BFLA on privileged endpoint POST /api/v1/admin/users/{userId}/role
- **Category:** BFLA
- **Severity:** HIGH
- **Confidence:** MEDIUM
- **Endpoint:** `POST /api/v1/admin/users/{userId}/role`
- **Source:** `lib/api/routes.dart:18`

#### Attack Path Hops
1. `ep_dart_lib_api_routes_dart_18_POST`
1. `fn_lib_controllers_admin_controller_dart_updateUserRole`

#### Static AST Evidence
- Privileged path/role identifier present: ['admin']
- Source location: lib/api/routes.dart:18

#### Remediation Guidance
Implement declarative role-based access control (RBAC) middleware. Validate user privileges on the backend for every privileged/administrative route.

---

### [TR-MASS-004] Potential Mass Assignment on POST /api/v1/admin/users/{userId}/role
- **Category:** MASS_ASSIGNMENT
- **Severity:** MEDIUM
- **Confidence:** MEDIUM
- **Endpoint:** `POST /api/v1/admin/users/{userId}/role`
- **Source:** `lib/api/routes.dart:18`

#### Attack Path Hops
1. `ep_dart_lib_api_routes_dart_18_POST`
1. `fn_lib_controllers_admin_controller_dart_updateUserRole`

#### Static AST Evidence
- State modifying method POST on profile/user path
- Model payload deserialization detected

#### Remediation Guidance
Define explicit request DTO schemas (e.g. Pydantic models with only allowed mutable fields). Do not allow raw dictionary binding directly into database models.

---

### [TR-CORS-005] Potential CORS Misconfiguration on POST /api/v1/admin/users/{userId}/role
- **Category:** CORS
- **Severity:** MEDIUM
- **Confidence:** MEDIUM
- **Endpoint:** `POST /api/v1/admin/users/{userId}/role`
- **Source:** `lib/api/routes.dart:18`

#### Attack Path Hops
1. `ep_dart_lib_api_routes_dart_18_POST`
1. `fn_lib_controllers_admin_controller_dart_updateUserRole`

#### Static AST Evidence
- Authenticated: True, Sensitive data: True

#### Remediation Guidance
Review access control and input validation on this attack path.

---

### [TR-BFLA-006] Potential BFLA on privileged endpoint POST /api/v1/integrations/webhooks/preview
- **Category:** BFLA
- **Severity:** HIGH
- **Confidence:** MEDIUM
- **Endpoint:** `POST /api/v1/integrations/webhooks/preview`
- **Source:** `lib/api/routes.dart:22`

#### Attack Path Hops
1. `ep_dart_lib_api_routes_dart_22_POST`
1. `fn_lib_controllers_webhook_controller_dart_previewWebhookEndpoint`

#### Static AST Evidence
- Privileged path/role identifier present: ['admin']
- Source location: lib/api/routes.dart:22

#### Remediation Guidance
Implement declarative role-based access control (RBAC) middleware. Validate user privileges on the backend for every privileged/administrative route.

---

### [TR-SSTI-007] Potential Template Injection on POST /api/v1/integrations/webhooks/preview
- **Category:** SSTI
- **Severity:** CRITICAL
- **Confidence:** MEDIUM
- **Endpoint:** `POST /api/v1/integrations/webhooks/preview`
- **Source:** `lib/api/routes.dart:22`

#### Attack Path Hops
1. `ep_dart_lib_api_routes_dart_22_POST`
1. `fn_lib_controllers_webhook_controller_dart_previewWebhookEndpoint`

#### Static AST Evidence
- Template rendering parameter detected: ['/api/v1/integrations/webhooks/preview']

#### Remediation Guidance
Review access control and input validation on this attack path.

---

### [TR-CORS-008] Potential CORS Misconfiguration on POST /api/v1/integrations/webhooks/preview
- **Category:** CORS
- **Severity:** MEDIUM
- **Confidence:** MEDIUM
- **Endpoint:** `POST /api/v1/integrations/webhooks/preview`
- **Source:** `lib/api/routes.dart:22`

#### Attack Path Hops
1. `ep_dart_lib_api_routes_dart_22_POST`
1. `fn_lib_controllers_webhook_controller_dart_previewWebhookEndpoint`

#### Static AST Evidence
- Authenticated: True, Sensitive data: True

#### Remediation Guidance
Review access control and input validation on this attack path.

---

### [TR-BFLA-009] Potential BFLA on privileged endpoint POST /api/v1/billing/invoices/{invoiceId}/refund
- **Category:** BFLA
- **Severity:** HIGH
- **Confidence:** MEDIUM
- **Endpoint:** `POST /api/v1/billing/invoices/{invoiceId}/refund`
- **Source:** `lib/api/routes.dart:26`

#### Attack Path Hops
1. `ep_dart_lib_api_routes_dart_26_POST`
1. `fn_lib_controllers_billing_controller_dart_processInvoiceRefund`

#### Static AST Evidence
- Privileged path/role identifier present: ['admin']
- Source location: lib/api/routes.dart:26

#### Remediation Guidance
Implement declarative role-based access control (RBAC) middleware. Validate user privileges on the backend for every privileged/administrative route.

---

### [TR-CORS-010] Potential CORS Misconfiguration on POST /api/v1/billing/invoices/{invoiceId}/refund
- **Category:** CORS
- **Severity:** MEDIUM
- **Confidence:** MEDIUM
- **Endpoint:** `POST /api/v1/billing/invoices/{invoiceId}/refund`
- **Source:** `lib/api/routes.dart:26`

#### Attack Path Hops
1. `ep_dart_lib_api_routes_dart_26_POST`
1. `fn_lib_controllers_billing_controller_dart_processInvoiceRefund`

#### Static AST Evidence
- Authenticated: True, Sensitive data: True

#### Remediation Guidance
Review access control and input validation on this attack path.

---

### [TR-BFLA-011] Potential BFLA on privileged endpoint PUT /api/v1/users/profile
- **Category:** BFLA
- **Severity:** HIGH
- **Confidence:** MEDIUM
- **Endpoint:** `PUT /api/v1/users/profile`
- **Source:** `lib/api/routes.dart:30`

#### Attack Path Hops
1. `ep_dart_lib_api_routes_dart_30_PUT`
1. `fn_lib_controllers_user_controller_dart_updateUserProfile`

#### Static AST Evidence
- Privileged path/role identifier present: ['admin']
- Source location: lib/api/routes.dart:30

#### Remediation Guidance
Implement declarative role-based access control (RBAC) middleware. Validate user privileges on the backend for every privileged/administrative route.

---

### [TR-MASS-012] Potential Mass Assignment on PUT /api/v1/users/profile
- **Category:** MASS_ASSIGNMENT
- **Severity:** MEDIUM
- **Confidence:** MEDIUM
- **Endpoint:** `PUT /api/v1/users/profile`
- **Source:** `lib/api/routes.dart:30`

#### Attack Path Hops
1. `ep_dart_lib_api_routes_dart_30_PUT`
1. `fn_lib_controllers_user_controller_dart_updateUserProfile`

#### Static AST Evidence
- State modifying method PUT on profile/user path
- Model payload deserialization detected

#### Remediation Guidance
Define explicit request DTO schemas (e.g. Pydantic models with only allowed mutable fields). Do not allow raw dictionary binding directly into database models.

---

### [TR-TRAV-013] Potential Path Traversal on PUT /api/v1/users/profile
- **Category:** PATH_TRAVERSAL
- **Severity:** HIGH
- **Confidence:** MEDIUM
- **Endpoint:** `PUT /api/v1/users/profile`
- **Source:** `lib/api/routes.dart:30`

#### Attack Path Hops
1. `ep_dart_lib_api_routes_dart_30_PUT`
1. `fn_lib_controllers_user_controller_dart_updateUserProfile`

#### Static AST Evidence
- File/path parameter names detected: ['/api/v1/users/profile']
- Source location: lib/api/routes.dart:30

#### Remediation Guidance
Review access control and input validation on this attack path.

---

### [TR-CORS-014] Potential CORS Misconfiguration on PUT /api/v1/users/profile
- **Category:** CORS
- **Severity:** MEDIUM
- **Confidence:** MEDIUM
- **Endpoint:** `PUT /api/v1/users/profile`
- **Source:** `lib/api/routes.dart:30`

#### Attack Path Hops
1. `ep_dart_lib_api_routes_dart_30_PUT`
1. `fn_lib_controllers_user_controller_dart_updateUserProfile`

#### Static AST Evidence
- Authenticated: True, Sensitive data: True

#### Remediation Guidance
Review access control and input validation on this attack path.

---

### [TR-AUTH-015] Unauthenticated sensitive endpoint GET /api/v2/records/{recordId}
- **Category:** AUTHENTICATION
- **Severity:** CRITICAL
- **Confidence:** HIGH
- **Endpoint:** `GET /api/v2/records/{recordId}`
- **Source:** `src/main/kotlin/com/enterprise/portal/controller/RecordController.kt:15`

#### Attack Path Hops
1. `ep_jvm_src_main_kotlin_com_enterprise_portal_controller_RecordController_kt_15_GET`
1. `ext_ep_jvm_src_main_kotlin_com_enterprise_portal_controller_RecordController_kt_15_GET`

#### Static AST Evidence
- State-changing: False
- Sensitive data indicator: True
- No auth middleware or dependency detected

#### Remediation Guidance
Protect this route with authentication dependencies (e.g. `Depends(get_current_user)` or security middleware) to ensure unauthorized users cannot trigger state-changing or sensitive operations.

---

### [TR-SSRF-016] Potential SSRF on GET /api/v2/records/{recordId}
- **Category:** SSRF
- **Severity:** HIGH
- **Confidence:** HIGH
- **Endpoint:** `GET /api/v2/records/{recordId}`
- **Source:** `src/main/kotlin/com/enterprise/portal/controller/RecordController.kt:15`

#### Attack Path Hops
1. `ep_jvm_src_main_kotlin_com_enterprise_portal_controller_RecordController_kt_15_GET`
1. `ext_ep_jvm_src_main_kotlin_com_enterprise_portal_controller_RecordController_kt_15_GET`

#### Static AST Evidence
- Outbound HTTP client calls detected in handler body
- URL parameter detected: []

#### Remediation Guidance
Avoid making arbitrary outbound HTTP requests with user-controlled URLs. Implement a strict destination domain whitelist and block loopback/internal IP addresses (RFC 1918).

---

### [TR-AUTH-017] Unauthenticated sensitive endpoint POST /api/v2/records/export/dispatch
- **Category:** AUTHENTICATION
- **Severity:** CRITICAL
- **Confidence:** HIGH
- **Endpoint:** `POST /api/v2/records/export/dispatch`
- **Source:** `src/main/kotlin/com/enterprise/portal/controller/RecordController.kt:32`

#### Attack Path Hops
1. `ep_jvm_src_main_kotlin_com_enterprise_portal_controller_RecordController_kt_32_POST`
1. `ext_ep_jvm_src_main_kotlin_com_enterprise_portal_controller_RecordController_kt_32_POST`

#### Static AST Evidence
- State-changing: True
- Sensitive data indicator: True
- No auth middleware or dependency detected

#### Remediation Guidance
Protect this route with authentication dependencies (e.g. `Depends(get_current_user)` or security middleware) to ensure unauthorized users cannot trigger state-changing or sensitive operations.

---

### [TR-SSRF-018] Potential SSRF on POST /api/v2/records/export/dispatch
- **Category:** SSRF
- **Severity:** HIGH
- **Confidence:** HIGH
- **Endpoint:** `POST /api/v2/records/export/dispatch`
- **Source:** `src/main/kotlin/com/enterprise/portal/controller/RecordController.kt:32`

#### Attack Path Hops
1. `ep_jvm_src_main_kotlin_com_enterprise_portal_controller_RecordController_kt_32_POST`
1. `ext_ep_jvm_src_main_kotlin_com_enterprise_portal_controller_RecordController_kt_32_POST`

#### Static AST Evidence
- Outbound HTTP client calls detected in handler body
- URL parameter detected: []

#### Remediation Guidance
Avoid making arbitrary outbound HTTP requests with user-controlled URLs. Implement a strict destination domain whitelist and block loopback/internal IP addresses (RFC 1918).

---
