import 'package:flutter_test/flutter_test.dart';

import 'package:netguardian_client/detect/contact_discover.dart';
import 'package:netguardian_client/outreach/permission_email.dart';

void main() {
  test('extracts mailto and plaintext emails from HTML', () {
    const html = '''
      <a href="mailto:Sec@Example.com">x</a>
      Contact us at help@example.com today
      <img src="cid:foo@bar.png">
    ''';
    final emails = emailsFromHtml(html);
    expect(emails, containsAll(['sec@example.com', 'help@example.com']));
    expect(emails.any((e) => e.endsWith('.png')), isFalse);
  });

  test('parses security.txt Contact lines', () {
    const text = '''
Contact: mailto:security@example.com
Contact: https://example.com/contact
Contact: abuse@example.com
''';
    expect(
      emailsFromSecurityTxt(text),
      ['security@example.com', 'abuse@example.com'],
    );
  });

  test('guesses support-style aliases', () {
    expect(
      guessedSupportEmails('owasp.org'),
      ['security@owasp.org', 'support@owasp.org', 'abuse@owasp.org'],
    );
  });

  test('builds yes/no permission email with consent URL', () {
    final draft = buildPermissionEmail(
      domainUrl: 'https://example.com/',
      contactEmail: 'support@example.com',
      consentUrl: 'http://127.0.0.1:8787/permission.html?token=abc',
    );
    expect(draft.to, 'support@example.com');
    expect(draft.subject.toLowerCase(), contains('permission'));
    expect(draft.body, contains('Would it be OK'));
    expect(draft.body, contains('Yes or No'));
    expect(draft.body, contains('permission.html?token=abc'));
    expect(draft.mailtoUri.scheme, 'mailto');
  });
}
