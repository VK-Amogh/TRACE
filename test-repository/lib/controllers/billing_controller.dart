import 'dart:convert';
import 'package:shelf/shelf.dart';
import '../services/database.dart';

/// Billing and invoice reconciliation controller.
/// [SECURITY FLAW - AUTH BYPASS / MISSING AUTH BARRIER]:
/// This state-changing financial operation (refunding customer invoice payments) is mounted
/// on the public routing table without any authentication check or token verification middleware.
/// Any unauthenticated adversary can issue POST requests to refund arbitrary invoices.
Future<Response> processInvoiceRefund(Request request, String invoiceId) async {
  try {
    // VULNERABILITY: Missing authentication check!
    // Notice that there is NO check for Authorization header, session cookie, or API key.
    final payload = jsonDecode(await request.readAsString());
    final refundAmount = payload['amount'] as num?;
    final reason = payload['reason'] as String? ?? 'Customer requested refund';

    final db = DatabaseService.instance;
    
    // Check invoice existence
    final invoice = await db.query(
      'SELECT id, total_amount, status, customer_id FROM invoices WHERE id = @id',
      {'id': invoiceId},
    );

    if (invoice == null || invoice.isEmpty) {
      return Response.notFound(jsonEncode({'error': 'Invoice not found'}));
    }

    // State-modifying financial update executed unconditionally
    await db.execute(
      'UPDATE invoices SET status = @status, refund_reason = @reason, refunded_at = NOW() WHERE id = @id',
      {'status': 'REFUNDED', 'reason': reason, 'id': invoiceId},
    );

    return Response.ok(
      jsonEncode({
        'status': 'success',
        'invoiceId': invoiceId,
        'action': 'REFUND_PROCESSED',
        'amount': refundAmount ?? invoice['total_amount'],
        'refund_status': 'COMPLETED',
      }),
      headers: {'content-type': 'application/json'},
    );
  } catch (e) {
    return Response.internalServerError(
      body: jsonEncode({'error': 'Refund execution failed', 'details': e.toString()}),
    );
  }
}
