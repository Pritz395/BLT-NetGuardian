/// Discover contact emails for permission outreach (client-side fetch).
library;

import 'package:http/http.dart' as http;

import 'domain_normalize.dart';

final _emailRe = RegExp(
  r'''\b([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,})\b''',
  caseSensitive: false,
);
final _mailtoRe = RegExp(
  r'''mailto:([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,})''',
  caseSensitive: false,
);

class ContactCandidate {
  const ContactCandidate({
    required this.email,
    required this.source,
  });

  final String email;
  final String source;
}

List<String> emailsFromHtml(String html) {
  final out = <String>[];
  final seen = <String>{};
  void add(String raw, {required String via}) {
    final email = raw.trim().toLowerCase();
    if (email.isEmpty || seen.contains(email)) return;
    if (email.endsWith('.png') ||
        email.endsWith('.jpg') ||
        email.endsWith('.gif') ||
        email.endsWith('.svg') ||
        email.endsWith('.webp')) {
      return;
    }
    seen.add(email);
    out.add(email);
  }

  for (final m in _mailtoRe.allMatches(html)) {
    add(m.group(1)!, via: 'mailto');
  }
  for (final m in _emailRe.allMatches(html)) {
    add(m.group(1)!, via: 'text');
  }
  return out;
}

List<String> emailsFromSecurityTxt(String text) {
  final out = <String>[];
  final seen = <String>{};
  for (final line in text.split('\n')) {
    if (!line.toLowerCase().startsWith('contact:')) continue;
    final value = line.substring(line.indexOf(':') + 1).trim();
    String email = '';
    if (value.toLowerCase().startsWith('mailto:')) {
      email = value.substring(7).trim().toLowerCase();
    } else {
      final m = _emailRe.firstMatch(value);
      email = (m?.group(1) ?? '').toLowerCase();
    }
    if (email.isEmpty || seen.contains(email)) continue;
    seen.add(email);
    out.add(email);
  }
  return out;
}

List<String> guessedSupportEmails(String hostKey) {
  final host = hostKey.trim().toLowerCase();
  if (host.isEmpty || !host.contains('.')) return const [];
  return ['security@$host', 'support@$host', 'abuse@$host'];
}

/// Prefer security.txt contacts, then page mailto/emails, then support@ guesses.
Future<List<ContactCandidate>> discoverContacts(
  String seedUrl, {
  http.Client? client,
  Duration timeout = const Duration(seconds: 12),
}) async {
  final httpClient = client ?? http.Client();
  final owned = client == null;
  final parsed = normalizeDomain(seedUrl);
  if (parsed == null) return const [];
  final origin = Uri.parse(parsed.seedUrl);
  final ranked = <ContactCandidate>[];
  final seen = <String>{};

  void push(String email, String source) {
    final e = email.trim().toLowerCase();
    if (e.isEmpty || seen.contains(e)) return;
    seen.add(e);
    ranked.add(ContactCandidate(email: e, source: source));
  }

  try {
    for (final path in ['/.well-known/security.txt', '/security.txt']) {
      try {
        final res = await httpClient
            .get(origin.replace(path: path))
            .timeout(timeout);
        if (res.statusCode >= 200 && res.statusCode < 300) {
          for (final e in emailsFromSecurityTxt(res.body)) {
            push(e, 'security.txt');
          }
          if (ranked.isNotEmpty) break;
        }
      } catch (_) {}
    }

    try {
      final res = await httpClient.get(origin).timeout(timeout);
      if (res.statusCode >= 200 && res.statusCode < 400) {
        for (final e in emailsFromHtml(res.body)) {
          push(e, 'page');
        }
      }
    } catch (_) {}

    for (final e in guessedSupportEmails(parsed.hostKey)) {
      push(e, 'guessed');
    }
  } finally {
    if (owned) httpClient.close();
  }
  return ranked;
}
