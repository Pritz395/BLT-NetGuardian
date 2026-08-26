/// Permission-ask email draft helpers.
library;

class PermissionEmailDraft {
  const PermissionEmailDraft({
    required this.to,
    required this.subject,
    required this.body,
  });

  final String to;
  final String subject;
  final String body;

  Uri get mailtoUri {
    return Uri(
      scheme: 'mailto',
      path: to,
      queryParameters: {
        'subject': subject,
        'body': body,
      },
    );
  }
}

const permissionTermsVersion = 'ng-permission-v1';

const permissionTermsText =
    "By selecting Yes, you confirm you are authorized to speak for this "
    "domain and grant the OWASP BLT / NetGuardian open-source community "
    "permission to perform non-destructive security review of publicly "
    "reachable pages and headers for this site. You may revoke permission "
    "by contacting the researcher. Scans stay on researcher-operated "
    "clients; NetGuardian does not fetch your site from the Worker. "
    "Findings may be shared with you for remediation and, with your "
    "agreement, handled under responsible disclosure practices.";

PermissionEmailDraft buildPermissionEmail({
  required String domainUrl,
  required String contactEmail,
  required String consentUrl,
}) {
  final subject = 'Permission to review security of $domainUrl?';
  final body = '''
Hello,

We are part of the OWASP BLT / NetGuardian open-source community. Our goal is to help make the web safer by spotting common misconfigurations (for example missing security headers) on sites whose owners welcome a closer look.

Would it be OK if we took a further look at the security of $domainUrl?

Please choose Yes or No here (Yes also means you agree to the short terms on that page):
$consentUrl

Thank you for helping keep the web safer.
— NetGuardian / OWASP BLT community
''';
  return PermissionEmailDraft(
    to: contactEmail,
    subject: subject,
    body: body.trim(),
  );
}
