# Authorization Server (OpenID Provider)

The **OpenID Provider (OP)** for the demo. It authenticates users and issues the artifacts of the
OIDC Authorization Code flow: short-lived authorization codes, RS256-signed **ID tokens** and
**access tokens**, plus the standard discovery and key-publishing endpoints.

- **Port:** `9000`
- **Issuer (`iss`):** `http://localhost:9000`
- **Signing:** RSA / RS256, keys generated at startup and published as a JWK Set.

This is a hand-rolled OP (no Spring Authorization Server dependency) so the protocol is explicit.

---

## Endpoints

| Method | Path                                      | Purpose                                                                 |
|--------|-------------------------------------------|-------------------------------------------------------------------------|
| `GET`  | `/.well-known/openid-configuration`       | Discovery document — advertises issuer, endpoints, and capabilities.    |
| `GET`  | `/.well-known/jwks.json`                   | JWK Set — public RSA keys used to verify token signatures.              |
| `GET`  | `/authorize`                              | Authorization endpoint — validates the request and shows the login page.|
| `POST` | `/login`                                  | Authenticates the user and redirects back with an authorization code.   |
| `POST` | `/token`                                  | Token endpoint — `authorization_code` **or** `refresh_token` grant.     |
| `GET`  | `/userinfo`                               | UserInfo endpoint — returns claims for a valid access token.            |

### `/authorize` (GET)

Validates the incoming OAuth params and, if good, renders the login form. Expected query params:

- `response_type=code`
- `client_id` — must be a registered client (`demo-client`)
- `redirect_uri` — must exactly match one registered for the client
- `scope` — space-delimited; must include `openid`
- `state` — opaque value echoed back to the client (CSRF protection)
- `code_challenge` + `code_challenge_method=S256` — PKCE

### `/login` (POST)

Verifies the submitted username/password against the user registry. On success it mints a one-time
authorization code (bound to the client, redirect URI, scopes, user, nonce and PKCE challenge) and
302-redirects to `redirect_uri?code=…&state=…`.

### `/token` (POST)

`application/x-www-form-urlencoded`. The client authenticates with HTTP Basic
(`client_secret_basic`) and chooses a grant:

**`grant_type=authorization_code`** — validates the code, redirect URI, and the **PKCE
`code_verifier`** against the stored challenge, then returns JSON:

```json
{
  "access_token": "<JWT>",
  "token_type": "Bearer",
  "expires_in": 300,
  "id_token": "<JWT>",
  "refresh_token": "<opaque>",
  "scope": "openid profile email api.read"
}
```

**`grant_type=refresh_token`** — trades a valid, unexpired `refresh_token` for a fresh access token
(and ID token) **without a new login**. Returns the same shape, including a **new** `refresh_token`.

```bash
curl -X POST http://localhost:9000/token \
  -u 'demo-client:demo-secret' \
  -d 'grant_type=refresh_token' \
  -d 'refresh_token=<opaque>'
```

Authorization codes are single-use and expire after 60 seconds.

### Refresh tokens — opaque, rotating, revocable

Unlike the access/ID tokens (stateless JWTs), the **refresh token is an opaque random string** held
server-side in `RefreshTokenStore`. That single design choice gives the OP two powers JWTs can't:

- **Rotation** — each refresh token is **single-use**. Redeeming it consumes the record and issues a
  new one, so a captured-and-replayed token fails on its second use (`invalid_grant`).
- **Revocation** — deleting the server-side record invalidates the token *immediately*, without
  waiting for an `exp` to pass. (This demo stores them in memory; a real OP uses a database.)

The record binds the token to its user, client, scope, and original nonce; the refresh grant checks
the token exists, is unexpired, and belongs to the authenticating client before minting anything.

---

## Seeded data

**Client** (`ClientRegistry`):

| client_id     | client_secret | redirect URI                      | scopes                           |
|---------------|---------------|-----------------------------------|----------------------------------|
| `demo-client` | `demo-secret` | `http://localhost:8080/callback`  | `openid profile email api.read`  |

**Users** (`UserRegistry`):

| subject    | username | password   | name           | email             |
|------------|----------|------------|----------------|-------------------|
| `user-001` | `alice`  | `password` | Alice Anderson | alice@example.com |
| `user-002` | `bob`    | `password` | Bob Brown      | bob@example.com   |

---

## Tokens

Both tokens are RS256 JWTs signed with a key generated at startup (`RsaKeyService`).

- **ID token** — `aud` = the client (`demo-client`), carries identity claims (`sub`, `name`, `email`,
  `nonce`, …). Consumed by the client app.
- **Access token** — `aud` = `resource-server`, carries `scope`, `sub`, and `client_id`. Consumed by
  the resource server.
- **Refresh token** — opaque (not a JWT), stored server-side; used to mint fresh access/ID tokens.

Lifetimes (configurable in `application.yml`): authorization code 60s, access token 300s, ID token
300s, refresh token 3600s.

---

## Key source files

```
authserver/
├── web/
│   ├── AuthorizationController.java  # /authorize + /login
│   ├── TokenController.java          # /token
│   ├── UserInfoController.java       # /userinfo
│   └── DiscoveryController.java      # /.well-known/{openid-configuration,jwks.json}
├── service/
│   ├── TokenService.java             # builds & signs ID/access tokens
│   └── PkceValidator.java            # verifies S256 code_verifier ↔ code_challenge
├── key/RsaKeyService.java            # RSA keypair + JWK Set
├── store/                            # in-memory clients, users, codes, refresh tokens
│   └── RefreshTokenStore.java        # opaque refresh tokens: issue + single-use consume (rotation)
├── model/                            # OidcClient, OidcUser, AuthorizationCode, RefreshToken
└── config/AuthServerProperties.java  # binds the `oidc.*` settings
```

---

## Configuration (`application.yml`)

```yaml
server:
  port: 9000
oidc:
  issuer: http://localhost:9000
  authorization-code-ttl-seconds: 60
  access-token-ttl-seconds: 300
  id-token-ttl-seconds: 300
  refresh-token-ttl-seconds: 3600
```

---

## Run

```bash
mvn spring-boot:run
```

Start this **before** the client app and resource server — both fetch this server's discovery
document and JWK Set at runtime.
