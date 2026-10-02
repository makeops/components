# Backend auth API

Contract for the auth service used by this app’s `Auth` client (`src/lib/server/auth`).

The Svelte app stores the bearer token returned from verify in an httpOnly cookie. The backend does not set browser cookies for this app.

## Configuration

| Variable (app) | Meaning |
| --- | --- |
| `AUTH_API_ORIGIN` | Optional. Base URL of the auth service (no trailing slash), e.g. `https://auth.example.com`. If unset, the app uses its own origin (same-host or reverse-proxy setup). |

| Variable (backend) | Meaning |
| --- | --- |
| `APP_ORIGIN` | Optional if the client sends `callbackUrl`. Used when building magic links server-side. |

## Conventions

- JSON request bodies: `Content-Type: application/json`
- Authenticated routes: `Authorization: Bearer <token>` where `<token>` is the opaque string from verify (often a JWT; clients must not parse it)
- Success with no body: HTTP `204` and empty body
- Error body (all endpoints):

```json
{ "error": "Short message safe to show users" }
```

| Status | When |
| --- | --- |
| `400` | Invalid input or unusable magic-link token |
| `401` | Missing or invalid bearer token (where the route requires auth) |
| `204` | Success, no response body |
| `200` | Success with JSON body |

## Magic-link flow

1. App → `POST /api/auth/magic-link` with email and callback URL.
2. Backend queues/sends email. On success responds `204` with **no body**.
3. **Dev/testing:** backend logs the full magic-link URL (same URL that would be emailed). Never return it in the HTTP response.
4. Link format: `{callbackUrl}?token=<one-time-token>` (query name `token`).
5. User opens link → app → `POST /api/auth/verify` with the one-time token.
6. Backend responds `{ "token": "<bearer>" }`. App stores bearer and uses it on later calls.

Use `204` for magic-link even when the email is unknown (avoid account enumeration).

---

## Endpoints

### `POST /api/auth/magic-link`

Request:

```json
{
  "email": "user@example.com",
  "callbackUrl": "https://app.example/auth/callback"
}
```

| Field | Rules |
| --- | --- |
| `email` | Required. Normalised email (app sends lowercased trimmed). |
| `callbackUrl` | Required. Absolute HTTPS URL (app may use `http` in local dev). No query string; backend appends `?token=…`. |

Success: **`204`**, empty body.

Errors: **`400`** `{ "error": "…" }` (malformed email or callback URL).

Backend log line (dev): include email and full magic-link URL, e.g.
`[magic-link] email=user@example.com url=https://app.example/auth/callback?token=…`

---

### `POST /api/auth/verify`

Exchange a one-time magic-link token for a session bearer token.

Request:

```json
{ "token": "<one-time-token>" }
```

Success: **`200`**

```json
{ "token": "<bearer>" }
```

| Field | Meaning |
| --- | --- |
| `token` | Opaque session token (JWT or other). Sent as `Authorization: Bearer` on subsequent requests. |

Errors: **`400`** `{ "error": "…" }` — missing token, unknown token, expired, or already used.

---

### `GET /api/auth/session`

Resolve the current user for a bearer token.

Headers: `Authorization: Bearer <bearer>` (required)

Success: **`200`**

Logged in:

```json
{ "email": "user@example.com" }
```

Not logged in / invalid token:

```json
{ "email": null }
```

Use **`200`** with `email: null` for invalid or expired bearer tokens (not `401`), so the app can clear local session without treating it as a transport error.

Errors: **`401`** `{ "error": "…" }` — only when the `Authorization` header is missing or not a Bearer token.

---

### `POST /api/auth/logout`

Invalidate the bearer token on the server (if your backend tracks sessions).

Headers: `Authorization: Bearer <bearer>` (required)

Success: **`204`**, empty body.

Errors: **`401`** `{ "error": "…" }` — missing or malformed auth header. Invalid/expired token may still return **`204`** (idempotent logout).

The app clears its cookie regardless.

---

### `GET /api/account`

Example protected resource: current account.

Headers: `Authorization: Bearer <bearer>` (required)

Success: **`200`**

```json
{ "email": "user@example.com" }
```

Errors:

- **`401`** `{ "error": "…" }` — missing header, invalid bearer, or expired session
- **`400`** — only if you extend the payload later; not used by this app today

---

## Client mapping

| `Auth` method | HTTP |
| --- | --- |
| `Auth.requestMagicLink` | `POST /api/auth/magic-link` |
| `Auth.verifyMagicLink` | `POST /api/auth/verify` → returns `token` string |
| `Auth.getSession` | `GET /api/auth/session` (skips call if no local bearer) |
| `Auth.logout` | `POST /api/auth/logout` (skips call if no local bearer) |
| `Auth.getAccount` | `GET /api/account` |
