"""Permission outreach unit tests."""

from permission_service import (
    TERMS_VERSION,
    build_permission_email,
    extract_emails_from_html,
    extract_emails_from_security_txt,
    guessed_support_emails,
)


def test_extract_emails_from_html():
    html = '<a href="mailto:Sec@Example.com">x</a> write help@example.com'
    assert extract_emails_from_html(html) == ["sec@example.com", "help@example.com"]


def test_security_txt_contacts():
    text = "Contact: mailto:security@example.com\nContact: abuse@example.com\n"
    assert extract_emails_from_security_txt(text) == [
        "security@example.com",
        "abuse@example.com",
    ]


def test_guessed_support():
    assert guessed_support_emails("owasp.org")[1] == "support@owasp.org"


def test_email_draft_has_yes_no_link():
    email = build_permission_email(
        domain_url="https://example.com/",
        contact_email="support@example.com",
        consent_url="http://127.0.0.1:8787/permission.html?token=abc",
    )
    assert "Would it be OK" in email["body"]
    assert "Yes or No" in email["body"]
    assert "permission.html?token=abc" in email["body"]
    assert email["to"] == "support@example.com"
    assert TERMS_VERSION.startswith("ng-permission")
