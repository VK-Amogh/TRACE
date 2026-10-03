import 'dart:io';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as io;
import 'api/routes.dart';

void main() async {
  final router = buildApiRouter();

  final handler = const Pipeline()
      .addMiddleware(logRequests())
      .addHandler(router);

  final port = int.tryParse(Platform.environment['PORT'] ?? '18082') ?? 18082;
  final server = await io.serve(handler, InternetAddress.anyIPv4, port);
  print('Enterprise Cloud Portal active on port ${server.port}');
}
