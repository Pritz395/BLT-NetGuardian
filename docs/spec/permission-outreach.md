# Permission outreach (site-owner Yes/No)

Researchers ask permission before a deeper look. Contact may come from
`security.txt`, page `mailto:`/emails, or a guessed `support@` / `security@`.

## Flow

1. Client discovers contacts for the seed domain
2. `POST /api/permission/invite` creates a tokenized invite + email draft
3. Researcher sends the draft (mailto / copy)
4. Owner opens `/permission.html?token=…` → **Yes** (must accept terms) or **No**
5. `POST /api/permission/invite/{token}/respond` records `accepted` / `declined`

## Terms

Version `ng-permission-v1` (see `permission_service.TERMS_TEXT`). Yes requires
`accepted_terms: true`.

## API

| Method | Path | Auth |
|--------|------|------|
| POST | `/api/permission/invite` | Bearer org token |
| GET | `/api/permission` | Bearer |
| GET | `/api/permission/invite/{token}` | public |
| POST | `/api/permission/invite/{token}/respond` | public |

## Migration

`migrations/0007_permission_consent.sql`
