import 'dart:convert';
import 'package:shelf/shelf.dart';
import '../services/database.dart';

/// Administrative role assignment controller.
/// [SECURITY FLAW - BFLA]: Broken Function-Level Authorization.
/// This endpoint modifies user RBAC roles, but fails to check whether the calling user
/// actually holds administrative privileges (e.g. `role == 'ADMIN'`). Any authenticated user
/// can post to this endpoint and promote themselves or others to 'SUPER_ADMIN'.
Future<Response> updateUserRole(Request request, String userId) async {
  try {
    final authHeader = request.headers['authorization'];
    if (authHeader == null || !authHeader.startsWith('Bearer ')) {
      return Response.forbidden(jsonEncode({'error': 'Authentication required'}));
    }

    final body = jsonDecode(await request.readAsString());
    final newRole = body['role'];

    if (newRole == null) {
      return Response.badRequest(body: jsonEncode({'error': 'Target role is required'}));
    }

    // VULNERABILITY: Missing Role check!
    // It verifies that a token was passed, but DOES NOT verify that the requester is an ADMIN.
    final db = DatabaseService.instance;
    await db.execute(
      'UPDATE users SET role = @role, updated_at = NOW() WHERE id = @id',
      {'role': newRole, 'id': userId},
    );

    return Response.ok(
      jsonEncode({
        'status': 'updated',
        'userId': userId,
        'assignedRole': newRole,
        'message': 'Role escalation successful',
      }),
      headers: {'content-type': 'application/json'},
    );
  } catch (e) {
    return Response.internalServerError(
      body: jsonEncode({'error': 'Failed to execute administrative update', 'details': e.toString()}),
    );
  }
}
