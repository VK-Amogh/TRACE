import 'dart:convert';
import 'package:shelf/shelf.dart';
import '../services/database.dart';

/// User profile and account management controller.
/// [SECURITY FLAW - MASS ASSIGNMENT]:
/// This endpoint accepts a client-provided JSON map and applies it directly to the user record
/// without a DTO whitelist or field filtering. An attacker can inject fields like `is_admin: true`,
/// `account_balance: 999999`, or `tier: "ENTERPRISE"` into the request body.
Future<Response> updateUserProfile(Request request) async {
  try {
    final authHeader = request.headers['authorization'];
    if (authHeader == null || !authHeader.startsWith('Bearer ')) {
      return Response.forbidden(jsonEncode({'error': 'Bearer token required'}));
    }

    final rawPayload = jsonDecode(await request.readAsString()) as Map<String, dynamic>;
    final db = DatabaseService.instance;

    // VULNERABILITY: Directly merging untrusted fields into database update query!
    // Allows overwriting sensitive attributes such as role, is_admin, or credit_balance.
    final updates = <String, dynamic>{};
    for (final entry in rawPayload.entries) {
      updates[entry.key] = entry.value;
    }

    await db.execute(
      'UPDATE users SET attributes = @attributes, updated_at = NOW() WHERE token = @token',
      {'attributes': jsonEncode(updates), 'token': authHeader.replaceFirst('Bearer ', '')},
    );

    return Response.ok(
      jsonEncode({
        'status': 'updated',
        'profile': updates,
        'message': 'Profile fields applied successfully',
      }),
      headers: {'content-type': 'application/json'},
    );
  } catch (e) {
    return Response.internalServerError(
      body: jsonEncode({'error': 'Profile update failed', 'details': e.toString()}),
    );
  }
}
