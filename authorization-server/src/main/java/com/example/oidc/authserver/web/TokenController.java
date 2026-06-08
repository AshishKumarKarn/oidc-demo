package com.example.oidc.authserver.web;

import com.example.oidc.authserver.model.AuthorizationCode;
import com.example.oidc.authserver.model.OidcClient;
import com.example.oidc.authserver.model.OidcUser;
import com.example.oidc.authserver.service.PkceValidator;
import com.example.oidc.authserver.service.TokenService;
import com.example.oidc.authserver.store.AuthorizationCodeStore;
import com.example.oidc.authserver.store.ClientRegistry;
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
import java.util.Map;
import java.util.Optional;

/**
 * Implements the OIDC <b>token endpoint</b> ({@code POST /token}).
 *
 * <p>Exchanges a valid authorization code for an {@code id_token} + {@code access_token}. The
 * checks performed (in order) are the heart of the flow's security:
 * <ol>
 *   <li>only {@code grant_type=authorization_code} is supported;</li>
 *   <li>the client is authenticated (HTTP Basic or POST body credentials);</li>
 *   <li>the code exists, is unexpired, and is consumed (single-use);</li>
 *   <li>the code was issued to <em>this</em> client and the {@code redirect_uri} matches;</li>
 *   <li>the PKCE {@code code_verifier} reproduces the stored {@code code_challenge}.</li>
 * </ol>
 * Only then are tokens minted. Errors follow RFC 6749 ({@code {"error": ...}} with HTTP 400/401).
 */
@RestController
public class TokenController {

    private static final Logger log = LoggerFactory.getLogger(TokenController.class);

    private final ClientRegistry clientRegistry;
    private final UserRegistry userRegistry;
    private final AuthorizationCodeStore codeStore;
    private final PkceValidator pkceValidator;
    private final TokenService tokenService;

    public TokenController(ClientRegistry clientRegistry,
                           UserRegistry userRegistry,
                           AuthorizationCodeStore codeStore,
                           PkceValidator pkceValidator,
                           TokenService tokenService) {
        this.clientRegistry = clientRegistry;
        this.userRegistry = userRegistry;
        this.codeStore = codeStore;
        this.pkceValidator = pkceValidator;
        this.tokenService = tokenService;
    }

    @PostMapping(value = "/token", produces = "application/json")
    public ResponseEntity<Map<String, Object>> token(
            @RequestParam(value = "grant_type", required = false) String grantType,
            @RequestParam(value = "code", required = false) String code,
            @RequestParam(value = "redirect_uri", required = false) String redirectUri,
            @RequestParam(value = "code_verifier", required = false) String codeVerifier,
            @RequestParam(value = "client_id", required = false) String clientIdParam,
            @RequestParam(value = "client_secret", required = false) String clientSecretParam,
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader) {

        // 1. Grant type.
        if (!"authorization_code".equals(grantType)) {
            return error(HttpStatus.BAD_REQUEST, "unsupported_grant_type",
                    "Only authorization_code is supported");
        }

        // 2. Authenticate the client. Credentials may come from the Basic header or the POST body.
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

        // 3. Look up & atomically consume the code (single-use even on later failures).
        if (code == null) {
            return error(HttpStatus.BAD_REQUEST, "invalid_request", "Missing code");
        }
        Optional<AuthorizationCode> maybeCode = codeStore.consume(code);
        if (maybeCode.isEmpty()) {
            return error(HttpStatus.BAD_REQUEST, "invalid_grant", "Unknown or already-used code");
        }
        AuthorizationCode authCode = maybeCode.get();
        if (authCode.isExpired()) {
            return error(HttpStatus.BAD_REQUEST, "invalid_grant", "Authorization code expired");
        }

        // 4. The code must belong to this client and replay the same redirect_uri.
        if (!authCode.clientId().equals(client.clientId())) {
            return error(HttpStatus.BAD_REQUEST, "invalid_grant", "Code was not issued to this client");
        }
        if (!authCode.redirectUri().equals(redirectUri)) {
            return error(HttpStatus.BAD_REQUEST, "invalid_grant", "redirect_uri mismatch");
        }

        // 5. PKCE: the verifier must reproduce the stored challenge.
        if (!pkceValidator.verify(codeVerifier, authCode.codeChallenge(), authCode.codeChallengeMethod())) {
            return error(HttpStatus.BAD_REQUEST, "invalid_grant", "PKCE verification failed");
        }

        // All checks passed -> mint tokens.
        Optional<OidcUser> maybeUser = userRegistry.findBySubject(authCode.subject());
        if (maybeUser.isEmpty()) {
            return error(HttpStatus.BAD_REQUEST, "invalid_grant", "User no longer exists");
        }
        OidcUser user = maybeUser.get();

        String idToken = tokenService.createIdToken(user, client.clientId(), authCode.scope(), authCode.nonce());
        String accessToken = tokenService.createAccessToken(user, client.clientId(), authCode.scope());
        log.debug("Issued tokens for user={} client={}", user.username(), client.clientId());

        Map<String, Object> body = Map.of(
                "access_token", accessToken,
                "token_type", "Bearer",
                "expires_in", 300,
                "id_token", idToken,
                "scope", authCode.scope());
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
