import 'dart:convert';
import 'package:shelf/shelf.dart';
import '../services/database.dart';

/// Handles enterprise project retrieval across organizational workspaces.
/// [SECURITY FLAW - BOLA]: Direct object reference lookup fetches the project by
/// `projectId` from the primary relational store, but omits verifying that the
/// requesting principal's tenant context matches `project.organizationId`.
Future<Response> getOrganizationProject(Request request, String orgId, String projectId) async {
  try {
    final db = DatabaseService.instance;
    
    // Simulates auth token resolution
    final authHeader = request.headers['authorization'];
    if (authHeader == null || !authHeader.startsWith('Bearer ')) {
      return Response.forbidden(jsonEncode({'error': 'Unauthorized: Bearer token required'}));
    }

    // Database lookup: queries the project record directly by primary key
    final project = await db.query(
      'SELECT id, name, organization_id, budget, api_keys, confidential_notes FROM projects WHERE id = @id',
      {'id': projectId},
    );

    if (project == null || project.isEmpty) {
      return Response.notFound(jsonEncode({'error': 'Project record not found'}));
    }

    // VULNERABILITY: Missing tenant boundary assertion:
    // Notice how `orgId` from the route parameter and `project['organization_id']` are NEVER validated!
    // An authenticated user belonging to Tenant A can supply Tenant B's projectId and dump confidential data.
    return Response.ok(
      jsonEncode({
        'status': 'success',
        'data': {
          'id': project['id'],
          'organizationId': project['organization_id'],
          'name': project['name'],
          'budget': project['budget'],
          'confidentialNotes': project['confidential_notes'],
          'apiKeys': project['api_keys'],
        }
      }),
      headers: {'content-type': 'application/json'},
    );
  } catch (e) {
    return Response.internalServerError(
      body: jsonEncode({'error': 'Internal database query failure', 'details': e.toString()}),
    );
  }
}
