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
| `POST` | `/token`                                  | Token endpoint — exchanges a code (+ PKCE verifier) for tokens.         |
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

`application/x-www-form-urlencoded`, `grant_type=authorization_code`. Validates the code, the client
credentials, the redirect URI, and the **PKCE `code_verifier`** against the stored challenge, then
returns JSON:

```json
{
  "access_token": "<JWT>",
  "id_token": "<JWT>",
  "token_type": "Bearer",
  "expires_in": 300
}
```

Authorization codes are single-use and expire after 60 seconds.

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

Lifetimes (configurable in `application.yml`): authorization code 60s, access token 300s, ID token
300s.

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
├── store/                            # in-memory clients, users, authorization codes
├── model/                            # OidcClient, OidcUser, AuthorizationCode
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
```

---

## Run

```bash
mvn spring-boot:run
```

Start this **before** the client app and resource server — both fetch this server's discovery
document and JWK Set at runtime.
