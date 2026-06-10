# OIDC Demo — Authorization Code Flow with PKCE

A minimal, from-scratch implementation of the **OpenID Connect (OIDC) Authorization Code flow with
PKCE**, built with Spring Boot 3 and Java 21. It is split into the three roles defined by the OIDC /
OAuth 2.0 specs, each as an independent, runnable application:

| Module                  | Role (spec term)            | Port  | What it does                                                          |
|-------------------------|-----------------------------|-------|----------------------------------------------------------------------|
| `authorization-server`  | OpenID Provider (OP)        | 9000  | Authenticates users, issues authorization codes, ID & access tokens. |
| `client-app`            | Relying Party (RP) / Client | 8080  | A web app that logs users in via the OP and calls the API.           |
| `resource-server`       | Resource Server / API       | 9100  | A protected API that validates access tokens before serving data.    |

Nothing here is production-grade — it deliberately avoids Spring Security's autoconfigured OAuth
support so that **every step of the protocol is visible in plain code**: building the authorization
request, PKCE, exchanging the code, signing and validating JWTs, the discovery document, the JWK set,
scope-based authorization, and so on. The source is heavily commented for learning.

---

## The flow at a glance

```
   Browser            client-app (8080)        authorization-server (9000)      resource-server (9100)
      │                     │                            │                              │
      │  GET /login         │                            │                              │
      ├────────────────────►│  build PKCE + state        │                              │
      │                     │  302 → /authorize?…        │                              │
      │◄────────────────────┤                            │                              │
      │  GET /authorize?client_id&redirect_uri&          │                              │
      │      code_challenge&scope&state ────────────────►│  show login page             │
      │◄─────────────────────────────────────────────── │                              │
      │  POST /login (alice/password) ──────────────────►│  authenticate, mint CODE     │
      │◄─────────────────────────────────────────────── │  302 → /callback?code&state  │
      │  GET /callback?code&state                        │                              │
      ├────────────────────►│  POST /token               │                              │
      │                     │   (code + code_verifier) ─►│  verify PKCE, issue          │
      │                     │◄────────────────────────── │  id_token + access_token     │
      │                     │  validate id_token         │                              │
      │                     │  (sig, iss, aud, nonce)    │                              │
      │  session established │                            │                              │
      │  GET /profile        │  GET /api/me, /api/messages (Bearer access_token) ───────►│  validate JWT
      │                     │◄────────────────────────────────────────────────────────┤  via JWKS, serve
      │◄────────────────────┤                            │                              │
      │   …access token expires (API → 401)…             │                              │
      │                     │  POST /token grant_type=refresh_token ──►│  rotate + issue│
      │                     │◄──────────────────────────── new access + refresh token   │
```

1. **Authorization request** — the client generates a PKCE `code_verifier`/`code_challenge` and a
   `state`, then redirects the browser to the OP's `/authorize`.
2. **Authentication** — the OP shows a login page; the user submits credentials.
3. **Code issuance** — the OP redirects back to the client's `/callback` with a short-lived
   authorization `code` (and the original `state`).
4. **Token exchange** — the client calls the OP's `/token` endpoint with the code **and the PKCE
   `code_verifier`**. The OP verifies the verifier against the stored challenge and returns an
   **ID token** (who the user is), an **access token** (what the client may do), and a
   **refresh token** (to renew the access token later).
5. **ID token validation** — the client validates the ID token's RS256 signature (via the OP's JWK
   set), issuer, audience, expiry, and nonce, then establishes a session.
6. **API access** — the client calls the resource server with the access token as a
   `Authorization: Bearer …` header. The resource server validates the JWT against the OP's JWKS and
   enforces issuer, audience, expiry, and scope.
7. **Token refresh** — when the access token expires (the API returns `401`), the client trades its
   **refresh token** at `/token` (`grant_type=refresh_token`) for a fresh access token — silently, with
   no re-login. The OP **rotates** the refresh token on each use (single-use), so the client stores the
   new one each time.

---

## Prerequisites

- **JDK 21**
- **Maven 3.9+** (or use your IDE's bundled Maven)

There is no parent/aggregator POM — each module is built and run on its own.

---

## Running the demo

Open three terminals and start the services **in this order** (the client and resource server fetch
keys/metadata from the OP, so start the OP first):

```bash
# Terminal 1 — Authorization Server (OP)
cd authorization-server && mvn spring-boot:run

# Terminal 2 — Resource Server (API)
cd resource-server && mvn spring-boot:run

# Terminal 3 — Client App (RP)
cd client-app && mvn spring-boot:run
```

Then open **http://localhost:8080** and click **Login**.

### Demo credentials

| Username | Password   | Name           | Email               |
|----------|------------|----------------|---------------------|
| `alice`  | `password` | Alice Anderson | alice@example.com   |
| `bob`    | `password` | Bob Brown      | bob@example.com     |

### Registered client

| Field           | Value                              |
|-----------------|------------------------------------|
| `client_id`     | `demo-client`                      |
| `client_secret` | `demo-secret`                      |
| redirect URI    | `http://localhost:8080/callback`   |
| scopes          | `openid profile email api.read`    |

(All of the above are seeded in-memory in the authorization server — see `ClientRegistry` and
`UserRegistry`.)

---

## Try it from the command line

Inspect the OP's discovery document and keys:

```bash
curl http://localhost:9000/.well-known/openid-configuration | jq
curl http://localhost:9000/.well-known/jwks.json | jq
```

Hit the resource server (public vs. protected):

```bash
# Public — no token needed
curl http://localhost:9100/

# Protected — 401 without a valid Bearer token
curl -i http://localhost:9100/api/me
```

To call the protected endpoints with a real token, log in through the browser flow; the client app's
profile page shows the data returned from `/api/me` and `/api/messages`.

---

## Module guides

Each module has its own README with endpoint reference and internals:

- [`authorization-server/README.md`](authorization-server/README.md) — issuing codes & tokens, PKCE, JWKS.
- [`client-app/README.md`](client-app/README.md) — building the auth request, token exchange, ID-token validation.
- [`resource-server/README.md`](resource-server/README.md) — bearer-token validation and scope enforcement.

---

## Configuration reference

All settings live in each module's `src/main/resources/application.yml`. Defaults wire the three
services together on `localhost`:

- OP issuer: `http://localhost:9000`
- Token lifetimes: authorization code 60s, access token 300s, ID token 300s, refresh token 3600s
- Access-token audience expected by the resource server: `resource-server`

---

## Project layout

```
oidc-demo/
├── authorization-server/   # OpenID Provider (port 9000)
├── client-app/             # Relying Party web app (port 8080)
└── resource-server/        # Protected API (port 9100)
```

> ⚠️ **For learning only.** Secrets are hard-coded, users and refresh tokens live in memory, tokens are
> unencrypted, and there is no HTTPS, consent screen, or persistence. Do not use any of this as-is in
> production.
