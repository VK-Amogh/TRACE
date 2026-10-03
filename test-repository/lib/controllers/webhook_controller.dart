import 'dart:convert';
import 'package:shelf/shelf.dart';
import 'package:http/http.dart' as http;

/// Integration webhook test controller.
/// [SECURITY FLAW - SSRF]: Server-Side Request Forgery.
/// The controller receives an arbitrary webhook URL from the client and triggers an outbound
/// HTTP GET request to test connectivity, without verifying whether the URL points to internal
/// IP addresses (e.g., 127.0.0.1, 169.254.169.254 AWS metadata, or RFC-1918 subnets).
Future<Response> previewWebhookEndpoint(Request request) async {
  try {
    final payload = jsonDecode(await request.readAsString());
    final targetUrl = payload['webhook_url'] as String?;

    if (targetUrl == null || targetUrl.isEmpty) {
      return Response.badRequest(body: jsonEncode({'error': 'webhook_url parameter missing'}));
    }

    // VULNERABILITY: Blind outbound HTTP request without IP address validation or DNS resolution checks!
    final client = http.Client();
    final uri = Uri.parse(targetUrl);
    
    // SINK: http.get triggers outbound network request to user-supplied endpoint
    final response = await client.get(uri).timeout(const Duration(seconds: 4));

    return Response.ok(
      jsonEncode({
        'status': 'dispatched',
        'target': targetUrl,
        'http_status': response.statusCode,
        'response_preview': response.body.length > 500 ? response.body.substring(0, 500) : response.body,
        'headers': response.headers,
      }),
      headers: {'content-type': 'application/json'},
    );
  } catch (e) {
    return Response.internalServerError(
      body: jsonEncode({'error': 'Webhook dispatch failed', 'details': e.toString()}),
    );
  }
}
