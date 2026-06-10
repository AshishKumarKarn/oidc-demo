# Client App (Relying Party)

The **Relying Party (RP)** — a Thymeleaf web app that logs users in through the OP using the
Authorization Code flow with PKCE, then calls the protected API on the user's behalf.

- **Port:** `8080`
- **Trusts OP:** `http://localhost:9000`
- **Calls API:** `http://localhost:9100`

Like the other modules, this avoids Spring Security's OAuth client autoconfiguration so each step —
building the request, PKCE, the token exchange, ID-token validation — is written out explicitly.

---

## Endpoints

| Method | Path        | Purpose                                                                            |
|--------|-------------|------------------------------------------------------------------------------------|
| `GET`  | `/`         | Home page; shows login link or current session.                                    |
| `GET`  | `/login`    | Starts the flow: generates PKCE + `state` + `nonce`, redirects to OP `/authorize`. |
| `GET`  | `/callback` | OAuth redirect URI: receives `code`, exchanges it for tokens, validates ID token.  |
| `GET`  | `/profile`  | Authenticated page; calls `/api/me` and `/api/messages` and displays results.      |
| `GET`  | `/logout`   | Clears the session.                                                                |

`/callback` is the registered `redirect_uri` (`http://localhost:8080/callback`).

---

## What happens during login

1. **`/login`** — `PkceService` creates a `code_verifier` and its S256 `code_challenge`; the app also
   generates `state` and `nonce`, stashes them in the session, and 302-redirects to the OP's
   `/authorize` with `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state`,
   `code_challenge` and `code_challenge_method=S256`.
2. **`/callback`** — verifies the returned `state` matches the session, then `TokenClient` POSTs to
   the OP's `/token` with the `code` and the original `code_verifier` to obtain the ID and access
   tokens.
3. **ID-token validation** — `IdTokenValidator` checks the RS256 signature (using keys discovered via
   `OidcDiscoveryService` → JWKS), and the `iss`, `aud`, `exp`, and `nonce` claims before trusting it.
4. **Session** — identity claims plus the access, ID, and **refresh** tokens are stored in the session;
   the user lands on `/profile`.
5. **API calls** — `ResourceServerClient` calls the resource server with
   `Authorization: Bearer <access_token>`.

### Silent token refresh

When the access token expires, a resource-server call returns **401**. `/profile` handles this
transparently: it calls `TokenClient.refresh(refreshToken)` to obtain a fresh access token (the OP
also returns a **rotated** refresh token, which replaces the stored one), then retries the API call —
**no re-login**. The profile page shows a "silently refreshed" banner when this happens. If the
refresh token itself is invalid/expired, the client clears the session and restarts the full login
flow. (To watch it happen quickly, set `oidc.access-token-ttl-seconds: 30` on the authorization
server and reload `/profile` after 30s.)

---

## Key source files

```
client/
├── web/LoginController.java          # /, /login, /callback, /profile, /logout
├── service/
│   ├── PkceService.java              # code_verifier / code_challenge (S256)
│   ├── OidcDiscoveryService.java     # fetches the OP discovery doc + JWKS
│   ├── TokenClient.java              # POSTs the code exchange + refresh_token grant to /token
│   ├── IdTokenValidator.java         # validates the ID token (sig, iss, aud, exp, nonce)
│   └── ResourceServerClient.java     # calls the protected API with the access token
├── config/ClientProperties.java      # binds the `oidc-client.*` settings
└── resources/templates/              # index, profile, error (Thymeleaf)
```

---

## Configuration (`application.yml`)

```yaml
server:
  port: 8080
oidc-client:
  issuer: http://localhost:9000
  client-id: demo-client
  client-secret: demo-secret
  redirect-uri: http://localhost:8080/callback
  scope: openid profile email api.read
  resource-server-url: http://localhost:9100
```

The `client-id` / `client-secret` / `redirect-uri` must match what the authorization server has
registered for this client.

---

## Run

```bash
mvn spring-boot:run
```

Make sure the **authorization server (9000)** and **resource server (9100)** are running first, then
visit **http://localhost:8080** and log in with `alice` / `password` (or `bob` / `password`).
