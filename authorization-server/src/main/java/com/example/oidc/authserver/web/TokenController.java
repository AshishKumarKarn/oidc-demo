package com.example.oidc.authserver.web;

import com.example.oidc.authserver.config.AuthServerProperties;
import com.example.oidc.authserver.model.AuthorizationCode;
import com.example.oidc.authserver.model.OidcClient;
import com.example.oidc.authserver.model.OidcUser;
import com.example.oidc.authserver.model.RefreshToken;
import com.example.oidc.authserver.service.PkceValidator;
import com.example.oidc.authserver.service.TokenService;
import com.example.oidc.authserver.store.AuthorizationCodeStore;
import com.example.oidc.authserver.store.ClientRegistry;
import com.example.oidc.authserver.store.RefreshTokenStore;
import com.example.oidc.authserver.store.UserRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Implements the OIDC <b>token endpoint</b> ({@code POST /token}).
 *
 * <p>Two grants are supported, both authenticated with client credentials (HTTP Basic
 * {@code client_secret_basic} or POST-body {@code client_secret_post}):
 *
 * <h3>{@code grant_type=authorization_code}</h3>
 * Exchanges a one-time authorization code for tokens. The checks (in order) are the heart of the
 * flow's security: the code exists/is unexpired and consumed (single-use); it was issued to
 * <em>this</em> client with the same {@code redirect_uri}; and the PKCE {@code code_verifier}
 * reproduces the stored {@code code_challenge}. On success the response includes an {@code id_token},
 * an {@code access_token}, and a {@code refresh_token}.
 *
 * <h3>{@code grant_type=refresh_token}</h3>
 * Trades a valid, unexpired refresh token for a fresh {@code access_token} (and {@code id_token})
 * without sending the user back through login. The presented refresh token is <b>rotated</b>: it is
 * consumed and a new one is issued, so a replayed token is detected on its second use.
 *
 * <p>Errors follow RFC 6749 ({@code {"error": ...}} with HTTP 400/401).
 */
@RestController
public class TokenController {

    private static final Logger log = LoggerFactory.getLogger(TokenController.class);

    private final ClientRegistry clientRegistry;
    private final UserRegistry userRegistry;
    private final AuthorizationCodeStore codeStore;
    private final RefreshTokenStore refreshTokenStore;
    private final PkceValidator pkceValidator;
    private final TokenService tokenService;
    private final AuthServerProperties properties;

    public TokenController(ClientRegistry clientRegistry,
                           UserRegistry userRegistry,
                           AuthorizationCodeStore codeStore,
                           RefreshTokenStore refreshTokenStore,
                           PkceValidator pkceValidator,
                           TokenService tokenService,
                           AuthServerProperties properties) {
        this.clientRegistry = clientRegistry;
        this.userRegistry = userRegistry;
        this.codeStore = codeStore;
        this.refreshTokenStore = refreshTokenStore;
        this.pkceValidator = pkceValidator;
        this.tokenService = tokenService;
        this.properties = properties;
    }

    @PostMapping(value = "/token", produces = "application/json")
    public ResponseEntity<Map<String, Object>> token(
            @RequestParam(value = "grant_type", required = false) String grantType,
            @RequestParam(value = "code", required = false) String code,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            @RequestParam(value = "code_verifier", required = false) String codeVerifier,
            @RequestParam(value = "refresh_token", required = false) String refreshTokenParam,
            @RequestParam(value = "client_id", required = false) String clientIdParam,
            @RequestParam(value = "client_secret", required = false) String clientSecretParam,
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader) {

        // Authenticate the client first — both grants require it.
        ClientCredentials credentials = resolveClientCredentials(
                authorizationHeader, clientIdParam, clientSecretParam);
        if (credentials == null) {
            return error(HttpStatus.UNAUTHORIZED, "invalid_client", "Missing client credentials");
        }
        Optional<OidcClient> maybeClient = clientRegistry.findByClientId(credentials.clientId());
        if (maybeClient.isEmpty() || !maybeClient.get().clientSecret().equals(credentials.clientSecret())) {
            return error(HttpStatus.UNAUTHORIZED, "invalid_client", "Client authentication failed");
        }
        OidcClient client = maybeClient.get();

        // Dispatch on the requested grant.
        if ("authorization_code".equals(grantType)) {
            return handleAuthorizationCode(client, code, redirectUri, codeVerifier);
        }
        if ("refresh_token".equals(grantType)) {
            return handleRefreshToken(client, refreshTokenParam);
        }
        return error(HttpStatus.BAD_REQUEST, "unsupported_grant_type",
                "Supported grants: authorization_code, refresh_token");
    }

    /** Handles {@code grant_type=authorization_code}: redeem a one-time code for tokens. */
    private ResponseEntity<Map<String, Object>> handleAuthorizationCode(
            OidcClient client, String code, String redirectUri, String codeVerifier) {

        if (code == null) {
            return error(HttpStatus.BAD_REQUEST, "invalid_request", "Missing code");
        }
        // Atomically consume the code (single-use even on later failures).
        Optional<AuthorizationCode> maybeCode = codeStore.consume(code);
        if (maybeCode.isEmpty()) {
            return error(HttpStatus.BAD_REQUEST, "invalid_grant", "Unknown or already-used code");
        }
        AuthorizationCode authCode = maybeCode.get();
        if (authCode.isExpired()) {
            return error(HttpStatus.BAD_REQUEST, "invalid_grant", "Authorization code expired");
        }
        // The code must belong to this client and replay the same redirect_uri.
        if (!authCode.clientId().equals(client.clientId())) {
            return error(HttpStatus.BAD_REQUEST, "invalid_grant", "Code was not issued to this client");
        }
        if (!authCode.redirectUri().equals(redirectUri)) {
            return error(HttpStatus.BAD_REQUEST, "invalid_grant", "redirect_uri mismatch");
        }
        // PKCE: the verifier must reproduce the stored challenge.
        if (!pkceValidator.verify(codeVerifier, authCode.codeChallenge(), authCode.codeChallengeMethod())) {
            return error(HttpStatus.BAD_REQUEST, "invalid_grant", "PKCE verification failed");
        }

        Optional<OidcUser> maybeUser = userRegistry.findBySubject(authCode.subject());
        if (maybeUser.isEmpty()) {
            return error(HttpStatus.BAD_REQUEST, "invalid_grant", "User no longer exists");
        }
        log.debug("Code redeemed for user={} client={}", maybeUser.get().username(), client.clientId());
        return issueTokens(maybeUser.get(), client, authCode.scope(), authCode.nonce());
    }

    /** Handles {@code grant_type=refresh_token}: rotate the token and mint a fresh access/ID token. */
    private ResponseEntity<Map<String, Object>> handleRefreshToken(OidcClient client, String refreshTokenValue) {
        if (refreshTokenValue == null || refreshTokenValue.isBlank()) {
            return error(HttpStatus.BAD_REQUEST, "invalid_request", "Missing refresh_token");
        }
        // Consume (rotate): a refresh token is single-use, so even a valid-looking replay fails here.
        Optional<RefreshToken> maybeToken = refreshTokenStore.consume(refreshTokenValue);
        if (maybeToken.isEmpty()) {
            return error(HttpStatus.BAD_REQUEST, "invalid_grant", "Unknown or already-used refresh token");
        }
        RefreshToken refreshToken = maybeToken.get();
        if (refreshToken.isExpired()) {
            return error(HttpStatus.BAD_REQUEST, "invalid_grant", "Refresh token expired");
        }
        // The token may only be used by the client it was issued to.
        if (!refreshToken.clientId().equals(client.clientId())) {
            return error(HttpStatus.BAD_REQUEST, "invalid_grant", "Refresh token was not issued to this client");
        }
        Optional<OidcUser> maybeUser = userRegistry.findBySubject(refreshToken.subject());
        if (maybeUser.isEmpty()) {
            return error(HttpStatus.BAD_REQUEST, "invalid_grant", "User no longer exists");
        }
        log.debug("Refresh token rotated for user={} client={}", maybeUser.get().username(), client.clientId());
        return issueTokens(maybeUser.get(), client, refreshToken.scope(), refreshToken.nonce());
    }

    /**
     * Mints the token set returned by both grants: a fresh access token + ID token, plus a newly
     * issued (rotated) refresh token. The same scope and nonce carry through so refreshed tokens are
     * indistinguishable from freshly-logged-in ones.
     */
    private ResponseEntity<Map<String, Object>> issueTokens(
            OidcUser user, OidcClient client, String scope, String nonce) {

        String idToken = tokenService.createIdToken(user, client.clientId(), scope, nonce);
        String accessToken = tokenService.createAccessToken(user, client.clientId(), scope);
        RefreshToken refresh = refreshTokenStore.issue(
                user.subject(), client.clientId(), scope, nonce, properties.getRefreshTokenTtlSeconds());

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("access_token", accessToken);
        body.put("token_type", "Bearer");
        body.put("expires_in", properties.getAccessTokenTtlSeconds());
        body.put("id_token", idToken);
        body.put("refresh_token", refresh.token());
        body.put("scope", scope);

        // OAuth requires token responses to be non-cacheable.
        return ResponseEntity.ok()
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .header(HttpHeaders.PRAGMA, "no-cache")
                .body(body);
    }

    /**
     * Extracts client credentials from either the HTTP Basic header ({@code client_secret_basic})
     * or the request body ({@code client_secret_post}). Returns null if neither is present.
     */
    private ClientCredentials resolveClientCredentials(String authorizationHeader,
                                                       String clientIdParam,
                                                       String clientSecretParam) {
        if (authorizationHeader != null && authorizationHeader.startsWith("Basic ")) {
            String base64 = authorizationHeader.substring("Basic ".length()).trim();
            String decoded = new String(Base64.getDecoder().decode(base64), StandardCharsets.UTF_8);
            int sep = decoded.indexOf(':');
            if (sep > 0) {
                return new ClientCredentials(decoded.substring(0, sep), decoded.substring(sep + 1));
            }
        }
        if (clientIdParam != null && clientSecretParam != null) {
            return new ClientCredentials(clientIdParam, clientSecretParam);
        }
        return null;
    }

    private ResponseEntity<Map<String, Object>> error(HttpStatus status, String error, String description) {
        return ResponseEntity.status(status)
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .body(Map.of("error", error, "error_description", description));
    }

    private record ClientCredentials(String clientId, String clientSecret) {
    }
}
