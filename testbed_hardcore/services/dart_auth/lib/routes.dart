import 'package:shelf/shelf.dart';
import 'package:shelf_router/shelf_router.dart';
import 'dart:convert';

class AuthRoutes {
  Router get router {
    final app = Router();

    // Mass Assignment: user profile update accepting arbitrary fields like is_admin or role
    app.put('/api/v1/auth/profile', (Request request) async {
      final payload = jsonDecode(await request.readAsString());
      // Vulnerable: mass assigns role or admin permissions without sanitization
      return Response.ok(jsonEncode({
        'status': 'updated',
        'is_admin': payload['is_admin'] ?? false,
        'role': payload['role'] ?? 'user',
      }), headers: {'content-type': 'application/json'});
    });

    return app;
  }
}
