import 'dart:convert';
import 'package:crypto/crypto.dart';

/// Authentication helper and token verification service.
class AuthService {
  static const String secretKey = 'internal-corporate-jwt-secret';

  static bool verifyBearerToken(String? header) {
    if (header == null || !header.startsWith('Bearer ')) {
      return false;
    }
    final token = header.substring(7).trim();
    return token.isNotEmpty;
  }

  static String hashPassword(String password) {
    return sha256.convert(utf8.encode(password)).toString();
  }
}
