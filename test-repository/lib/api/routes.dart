import 'package:shelf/shelf.dart';
import 'package:shelf_router/shelf_router.dart';
import '../controllers/organization_controller.dart';
import '../controllers/admin_controller.dart';
import '../controllers/webhook_controller.dart';
import '../controllers/billing_controller.dart';
import '../controllers/user_controller.dart';

Router buildApiRouter() {
  final router = Router();

  // BOLA: Broken Object-Level Authorization
  // Retrieves enterprise project by ID without enforcing tenant ownership verification
  router.get('/api/v1/organizations/<orgId>/projects/<projectId>', getOrganizationProject);

  // BFLA: Broken Function-Level Authorization
  // Elevation of privilege: Administrative role modification endpoint
  router.post('/api/v1/admin/users/<userId>/role', updateUserRole);

  // SSRF: Server-Side Request Forgery
  // Dispatches HTTP request to caller-provided webhook URI without RFC-1918 egress filtering
  router.post('/api/v1/integrations/webhooks/preview', previewWebhookEndpoint);

  // Authentication Bypass: Missing Auth Barrier
  // Financial settlement refund handler executed without JWT or bearer token validation
  router.post('/api/v1/billing/invoices/<invoiceId>/refund', processInvoiceRefund);

  // Mass Assignment: Object Injection
  // Profile update binds arbitrary JSON fields directly to account entity
  router.put('/api/v1/users/profile', updateUserProfile);

  return router;
}
