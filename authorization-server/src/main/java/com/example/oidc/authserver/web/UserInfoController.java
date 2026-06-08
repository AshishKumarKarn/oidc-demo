package com.example.oidc.authserver.web;

import com.example.oidc.authserver.key.RsaKeyService;
import com.example.oidc.authserver.model.OidcUser;
import com.example.oidc.authserver.store.UserRegistry;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Implements the OIDC <b>UserInfo endpoint</b> ({@code GET /userinfo}).
 *
 * <p>The client presents the access token as a Bearer token; we validate it (signature + expiry)
 * and return the user's claims, filtered by the scopes the access token was granted. {@code sub} is
 * always returned. {@code profile} adds {@code name}/{@code preferred_username}; {@code email} adds
 * {@code email}/{@code email_verified}.
 */
@RestController
public class UserInfoController {

    private final RsaKeyService rsaKeyService;
    private final UserRegistry userRegistry;

    public UserInfoController(RsaKeyService rsaKeyService, UserRegistry userRegistry) {
        this.rsaKeyService = rsaKeyService;
        this.userRegistry = userRegistry;
    }

    @GetMapping("/userinfo")
    public ResponseEntity<?> userInfo(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {

        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return unauthorized("missing_token");
        }
        String token = authorization.substring("Bearer ".length()).trim();

        try {
            SignedJWT jwt = SignedJWT.parse(token);

            // Verify the RS256 signature with our own public key.
            if (!jwt.verify(new RSASSAVerifier(rsaKeyService.getRsaKey().toPublicJWK()))) {
                return unauthorized("invalid_signature");
            }
            // Reject expired tokens.
            Date expiry = jwt.getJWTClaimsSet().getExpirationTime();
            if (expiry == null || expiry.before(new Date())) {
                return unauthorized("token_expired");
            }

            String subject = jwt.getJWTClaimsSet().getSubject();
            Optional<OidcUser> maybeUser = userRegistry.findBySubject(subject);
            if (maybeUser.isEmpty()) {
                return unauthorized("unknown_subject");
            }
            OidcUser user = maybeUser.get();

            // Filter claims by the granted scope (stored in the access token).
            String scope = Optional.ofNullable(jwt.getJWTClaimsSet().getStringClaim("scope")).orElse("");
            Set<String> scopes = Set.copyOf(Arrays.asList(scope.trim().isEmpty() ? new String[0] : scope.trim().split("\\s+")));

            Map<String, Object> claims = new HashMap<>();
            claims.put("sub", user.subject());
            if (scopes.contains("profile")) {
                claims.put("name", user.fullName());
                claims.put("preferred_username", user.username());
            }
            if (scopes.contains("email")) {
                claims.put("email", user.email());
                claims.put("email_verified", true);
            }
            return ResponseEntity.ok(claims);

        } catch (Exception e) {
            return unauthorized("invalid_token");
        }
    }

    /** RFC 6750 mandates a {@code WWW-Authenticate: Bearer} header on 401 responses. */
    private ResponseEntity<?> unauthorized(String error) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .header(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"" + error + "\"")
                .body(Map.of("error", error));
    }
}
