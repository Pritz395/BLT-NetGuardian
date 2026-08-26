/// Client API for permission invites.
library;

import 'dart:convert';

import 'package:http/http.dart' as http;

class PermissionInviteResult {
  const PermissionInviteResult({
    required this.consentUrl,
    required this.contactEmail,
    required this.contactSource,
    required this.status,
    required this.mailto,
    required this.subject,
    required this.body,
  });

  final String consentUrl;
  final String contactEmail;
  final String contactSource;
  final String status;
  final String mailto;
  final String subject;
  final String body;

  factory PermissionInviteResult.fromJson(Map<String, dynamic> json) {
    final invite = (json['invite'] as Map?)?.cast<String, dynamic>() ?? {};
    final email = (json['email'] as Map?)?.cast<String, dynamic>() ?? {};
    return PermissionInviteResult(
      consentUrl: '${invite['consent_url'] ?? ''}',
      contactEmail: '${invite['contact_email'] ?? ''}',
      contactSource: '${invite['contact_source'] ?? ''}',
      status: '${invite['status'] ?? 'pending'}',
      mailto: '${email['mailto'] ?? ''}',
      subject: '${email['subject'] ?? ''}',
      body: '${email['body'] ?? ''}',
    );
  }
}

Future<PermissionInviteResult> createPermissionInvite({
  required String baseUrl,
  required String domain,
  required String contactEmail,
  required String contactSource,
  String token = 'triage-token',
  String senderId = 'scanner-1',
  http.Client? client,
}) async {
  final httpClient = client ?? http.Client();
  final owned = client == null;
  try {
    final uri = Uri.parse('${baseUrl.replaceAll(RegExp(r'/+$'), '')}/api/permission/invite');
    final res = await httpClient.post(
      uri,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer $token',
      },
      body: jsonEncode({
        'domain': domain,
        'contact_email': contactEmail,
        'contact_source': contactSource,
        'sender_id': senderId,
      }),
    );
    final decoded = jsonDecode(res.body);
    if (res.statusCode >= 300 || decoded is! Map) {
      final msg = decoded is Map ? (decoded['message'] ?? decoded['error']) : res.body;
      throw StateError('permission invite failed (${res.statusCode}): $msg');
    }
    return PermissionInviteResult.fromJson(decoded.cast<String, dynamic>());
  } finally {
    if (owned) httpClient.close();
  }
}
