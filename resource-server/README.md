# Resource Server (Protected API)

The **Resource Server** — a JSON API that protects its `/api/**` routes with OAuth 2.0 bearer access
tokens. It validates each token as an RS256 JWT against the OP's published keys and enforces issuer,
audience, expiry, and scope. It never talks to the authorization server's private endpoints; it only
needs the public JWK Set.

- **Port:** `9100`
- **Trusts issuer:** `http://localhost:9000`
- **Expected audience (`aud`):** `resource-server`
- **Keys from:** `http://localhost:9000/.well-known/jwks.json`

---

## Endpoints

| Method | Path            | Auth                         | Purpose                                                        |
|--------|-----------------|------------------------------|----------------------------------------------------------------|
| `GET`  | `/`             | none (public)                | Health/info endpoint; contrasts with the protected routes.     |
| `GET`  | `/api/me`       | Bearer token                 | Returns `subject`, `clientId`, and `scopes` from the token.    |
| `GET`  | `/api/messages` | Bearer token + `api.read`    | Returns sample protected data; 403 if the scope is missing.    |

### Responses

`GET /` (public):

```json
{ "service": "resource-server", "status": "up", "hint": "Call /api/me or /api/messages with a Bearer access token" }
```

`GET /api/me`:

```json
{ "subject": "user-001", "clientId": "demo-client", "scopes": ["openid","profile","email","api.read"] }
```

`GET /api/messages` (requires `api.read`, otherwise `403 insufficient_scope`):

```json
{
  "servedAt": "2026-06-09T12:00:00Z",
  "owner": "user-001",
  "messages": [
    { "id": 1, "from": "system", "text": "Welcome, your token is valid!" },
    { "id": 2, "from": "system", "text": "This data is protected by an access token." }
  ]
}
```

A missing or invalid token yields `401 Unauthorized`.

---

## How tokens are validated

A servlet filter (`BearerTokenAuthenticationFilter`, wired only to `/api/*`) extracts the
`Authorization: Bearer …` header and hands the JWT to `AccessTokenValidator`, which uses Nimbus JOSE:

1. A self-refreshing `RemoteJWKSet` fetches and caches the OP's public keys from `jwks-uri`, so key
   rotation is handled automatically.
2. A `JWSVerificationKeySelector` accepts only **RS256** and resolves the key by the token's `kid`,
   then verifies the signature.
3. A `DefaultJWTClaimsVerifier` requires the exact `iss` and `aud`, and a valid (non-expired) `exp`.

On success the trusted claims are wrapped in an `AuthenticatedToken` and attached to the request;
controllers read it to enforce scope (e.g. `api.read` for `/api/messages`).

---

## Key source files

```
resourceserver/
├── web/
│   ├── PublicController.java                 # GET /
│   └── ApiController.java                     # GET /api/me, /api/messages
├── security/
│   ├── BearerTokenAuthenticationFilter.java   # extracts the Bearer token on /api/*
│   ├── AccessTokenValidator.java              # RS256 JWT validation via JWKS
│   └── AuthenticatedToken.java                # trusted claims placed on the request
└── config/
    ├── FilterConfig.java                       # registers the filter for /api/*
    └── ResourceServerProperties.java           # binds the `resource-server.*` settings
```

---

## Configuration (`application.yml`)

```yaml
server:
  port: 9100
resource-server:
  issuer: http://localhost:9000
  jwks-uri: http://localhost:9000/.well-known/jwks.json
  audience: resource-server
```

---

## Run

```bash
mvn spring-boot:run
```

Try it:

```bash
curl http://localhost:9100/             # public, 200
curl -i http://localhost:9100/api/me    # 401 without a token
```

To call the protected endpoints with a real access token, log in through the client app
(`http://localhost:8080`); its profile page surfaces the results of `/api/me` and `/api/messages`.
