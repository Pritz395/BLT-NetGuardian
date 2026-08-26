"""Permission outreach: invite site owners to consent before deeper review."""

from __future__ import annotations

import hashlib
import re
import secrets
from datetime import datetime, timezone
from typing import Any, Mapping, Optional

from auth import AuthError, resolve_org_auth_async
from domain_normalize import normalize_domain

TERMS_VERSION = "ng-permission-v1"
TERMS_TEXT = (
    "By selecting Yes, you confirm you are authorized to speak for this "
    "domain and grant the OWASP BLT / NetGuardian open-source community "
    "permission to perform non-destructive security review of publicly "
    "reachable pages and headers for this site. You may revoke permission "
    "by contacting the researcher. Scans stay on researcher-operated "
    "clients; NetGuardian does not fetch your site from the Worker. "
    "Findings may be shared with you for remediation and, with your "
    "agreement, handled under responsible disclosure practices."
)

_EMAIL_RE = re.compile(
    r"(?i)\b([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,})\b"
)
_MAILTO_RE = re.compile(r"(?i)mailto:([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,})")


class PermissionError(Exception):
    def __init__(self, message: str, *, status: int = 400, code: str = "bad_request"):
        self.message = message
        self.status = status
        self.code = code
        super().__init__(message)


def _now() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def error_body(exc: PermissionError | AuthError) -> tuple[int, dict]:
    if isinstance(exc, AuthError):
        return exc.status, exc.to_response_body()
    return exc.status, {"error": exc.code, "message": exc.message}


def extract_emails_from_html(html: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for match in _MAILTO_RE.finditer(html or ""):
        email = match.group(1).lower()
        if email not in seen:
            seen.add(email)
            found.append(email)
    for match in _EMAIL_RE.finditer(html or ""):
        email = match.group(1).lower()
        if email.endswith((".png", ".jpg", ".gif", ".svg", ".webp")):
            continue
        if email not in seen:
            seen.add(email)
            found.append(email)
    return found


def extract_emails_from_security_txt(text: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for line in (text or "").splitlines():
        if not line.lower().startswith("contact:"):
            continue
        value = line.split(":", 1)[1].strip()
        if value.lower().startswith("mailto:"):
            email = value.split(":", 1)[1].strip().lower()
        else:
            m = _EMAIL_RE.search(value)
            email = m.group(1).lower() if m else ""
        if email and email not in seen:
            seen.add(email)
            out.append(email)
    return out


def guessed_support_emails(host_key: str) -> list[str]:
    host = host_key.strip().lower()
    if not host or "." not in host:
        return []
    return [f"security@{host}", f"support@{host}", f"abuse@{host}"]


def build_permission_email(
    *,
    domain_url: str,
    contact_email: str,
    consent_url: str,
) -> dict[str, str]:
    subject = f"Permission to review security of {domain_url}?"
    body = (
        f"Hello,\n\n"
        f"We are part of the OWASP BLT / NetGuardian open-source community. "
        f"Our goal is to help make the web safer by spotting common "
        f"misconfigurations (for example missing security headers) on sites "
        f"whose owners welcome a closer look.\n\n"
        f"Would it be OK if we took a further look at the security of "
        f"{domain_url}?\n\n"
        f"Please choose Yes or No here (Yes also means you agree to the "
        f"short terms on that page):\n"
        f"{consent_url}\n\n"
        f"Thank you for helping keep the web safer.\n"
        f"— NetGuardian / OWASP BLT community\n"
    )
    return {
        "to": contact_email,
        "subject": subject,
        "body": body,
        "mailto": (
            f"mailto:{contact_email}"
            f"?subject={_q(subject)}&body={_q(body)}"
        ),
    }


def _q(value: str) -> str:
    from urllib.parse import quote

    return quote(value, safe="")


def _invite_id(org_id: str, host_key: str, token: str) -> str:
    return hashlib.sha256(f"{org_id}:{host_key}:{token}".encode()).hexdigest()[:16]


def _row(row: Any) -> dict:
    if row is None:
        return {}
    if isinstance(row, dict):
        return row
    keys = getattr(row, "keys", None)
    if callable(keys):
        return {k: row[k] for k in row.keys()}
    return dict(row)


class PermissionStore:
    def __init__(self, db: Any):
        self.db = db

    async def insert(self, row: Mapping[str, Any]) -> None:
        await self.db.prepare(
            """
            INSERT INTO permission_invites (
              id, org_id, host_key, domain_url, contact_email, contact_source,
              token, status, terms_version, created_at, updated_at, created_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
        ).bind(
            row["id"],
            row["org_id"],
            row["host_key"],
            row["domain_url"],
            row["contact_email"],
            row["contact_source"],
            row["token"],
            row["status"],
            row["terms_version"],
            row["created_at"],
            row["updated_at"],
            row.get("created_by"),
        ).run()

    async def by_token(self, token: str) -> Optional[dict]:
        res = await self.db.prepare(
            "SELECT * FROM permission_invites WHERE token = ?"
        ).bind(token).first()
        return _row(res) if res else None

    async def list_for_org(self, org_id: str, *, host_key: Optional[str] = None) -> list[dict]:
        if host_key:
            res = await self.db.prepare(
                """
                SELECT * FROM permission_invites
                WHERE org_id = ? AND host_key = ?
                ORDER BY created_at DESC LIMIT 50
                """
            ).bind(org_id, host_key).all()
        else:
            res = await self.db.prepare(
                """
                SELECT * FROM permission_invites
                WHERE org_id = ?
                ORDER BY created_at DESC LIMIT 50
                """
            ).bind(org_id).all()
        rows = getattr(res, "results", None) or res or []
        return [_row(r) for r in rows]

    async def respond(self, token: str, *, status: str, now: int) -> Optional[dict]:
        await self.db.prepare(
            """
            UPDATE permission_invites
            SET status = ?, updated_at = ?, responded_at = ?
            WHERE token = ? AND status = 'pending'
            """
        ).bind(status, now, now, token).run()
        return await self.by_token(token)


def _public_base(env: Any, headers: Mapping[str, str]) -> str:
    configured = str(getattr(env, "NG_PUBLIC_BASE_URL", "") or "").strip().rstrip("/")
    if configured:
        return configured
    origin = headers.get("Origin") or headers.get("origin") or ""
    if origin.startswith("http"):
        return origin.rstrip("/")
    # Workers often see Host without scheme
    host = headers.get("Host") or headers.get("host") or ""
    if host:
        return f"https://{host}"
    return "http://127.0.0.1:8787"


async def create_invite_for_request(
    *,
    env: Any,
    db: Any,
    headers: Mapping[str, str],
    body: Mapping[str, Any],
) -> tuple[int, dict]:
    ctx = await resolve_org_auth_async(env, headers, db=db)
    if db is None:
        raise PermissionError("database unavailable", status=503, code="no_db")
    raw_domain = str(body.get("domain") or body.get("url") or "").strip()
    parsed = normalize_domain(raw_domain)
    if parsed is None:
        raise PermissionError("invalid domain")
    host_key, domain_url = parsed
    contact_email = str(body.get("contact_email") or "").strip().lower()
    contact_source = str(body.get("contact_source") or "manual").strip()[:40]
    if not contact_email:
        guesses = guessed_support_emails(host_key)
        contact_email = guesses[1] if len(guesses) > 1 else (guesses[0] if guesses else "")
        contact_source = "guessed-support"
    if not _EMAIL_RE.fullmatch(contact_email):
        raise PermissionError("invalid contact_email")
    token = secrets.token_urlsafe(24)
    now = _now()
    invite_id = _invite_id(ctx.org_id, host_key, token)
    store = PermissionStore(db)
    await store.insert(
        {
            "id": invite_id,
            "org_id": ctx.org_id,
            "host_key": host_key,
            "domain_url": domain_url,
            "contact_email": contact_email,
            "contact_source": contact_source,
            "token": token,
            "status": "pending",
            "terms_version": TERMS_VERSION,
            "created_at": now,
            "updated_at": now,
            "created_by": str(body.get("sender_id") or "scanner-1")[:80],
        }
    )
    base = _public_base(env, headers)
    consent_url = f"{base}/permission.html?token={token}"
    email = build_permission_email(
        domain_url=domain_url,
        contact_email=contact_email,
        consent_url=consent_url,
    )
    return 200, {
        "invite": {
            "id": invite_id,
            "org_id": ctx.org_id,
            "host_key": host_key,
            "domain_url": domain_url,
            "contact_email": contact_email,
            "contact_source": contact_source,
            "status": "pending",
            "terms_version": TERMS_VERSION,
            "consent_url": consent_url,
            "created_at": now,
        },
        "email": email,
        "terms": {"version": TERMS_VERSION, "text": TERMS_TEXT},
    }


async def get_invite_public(*, db: Any, token: str) -> tuple[int, dict]:
    if db is None:
        raise PermissionError("database unavailable", status=503, code="no_db")
    store = PermissionStore(db)
    row = await store.by_token(token.strip())
    if not row:
        raise PermissionError("invite not found", status=404, code="not_found")
    return 200, {
        "domain_url": row["domain_url"],
        "host_key": row["host_key"],
        "status": row["status"],
        "terms": {"version": row["terms_version"], "text": TERMS_TEXT},
        "contact_email": row["contact_email"],
    }


async def respond_invite_public(
    *,
    db: Any,
    token: str,
    body: Mapping[str, Any],
) -> tuple[int, dict]:
    if db is None:
        raise PermissionError("database unavailable", status=503, code="no_db")
    decision = str(body.get("decision") or "").strip().lower()
    if decision not in {"yes", "no"}:
        raise PermissionError("decision must be yes or no")
    if decision == "yes" and not body.get("accepted_terms"):
        raise PermissionError("accepted_terms required when decision is yes")
    store = PermissionStore(db)
    existing = await store.by_token(token.strip())
    if not existing:
        raise PermissionError("invite not found", status=404, code="not_found")
    if existing["status"] != "pending":
        return 200, {
            "status": existing["status"],
            "message": "already responded",
            "domain_url": existing["domain_url"],
        }
    status = "accepted" if decision == "yes" else "declined"
    row = await store.respond(token.strip(), status=status, now=_now())
    return 200, {
        "status": row["status"] if row else status,
        "domain_url": existing["domain_url"],
        "terms_version": TERMS_VERSION if decision == "yes" else None,
    }


async def list_invites_for_request(
    *,
    env: Any,
    db: Any,
    headers: Mapping[str, str],
    query_params: Mapping[str, str],
) -> tuple[int, dict]:
    ctx = await resolve_org_auth_async(env, headers, db=db)
    if db is None:
        raise PermissionError("database unavailable", status=503, code="no_db")
    host = str(query_params.get("domain") or query_params.get("host") or "").strip()
    host_key = None
    if host:
        parsed = normalize_domain(host)
        if parsed is None:
            raise PermissionError("invalid domain filter")
        host_key = parsed[0]
    rows = await PermissionStore(db).list_for_org(ctx.org_id, host_key=host_key)
    return 200, {"org_id": ctx.org_id, "invites": rows}
