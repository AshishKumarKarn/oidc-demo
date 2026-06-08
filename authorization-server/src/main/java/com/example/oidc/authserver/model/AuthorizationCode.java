package com.example.oidc.authserver.model;

import java.time.Instant;

/**
 * Server-side record created at the authorization endpoint and consumed at the token endpoint.
 *
 * <p>The opaque {@code code} string handed back to the browser is just a lookup key; all the
 * security-sensitive context lives here on the server and is bound to that code:
 * <ul>
 *   <li>{@code subject} / {@code clientId} &ndash; who authenticated and for which client,</li>
 *   <li>{@code redirectUri} &ndash; must be replayed identically at the token endpoint,</li>
 *   <li>{@code scope} &ndash; what was granted,</li>
 *   <li>{@code nonce} &ndash; echoed into the ID token to bind it to this auth request,</li>
 *   <li>{@code codeChallenge} / {@code codeChallengeMethod} &ndash; PKCE binding to the original
 *       {@code code_verifier} so a stolen code cannot be redeemed by an attacker.</li>
 * </ul>
 */
public record AuthorizationCode(
        String code,
        String subject,
        String clientId,
        String redirectUri,
        String scope,
        String nonce,
        String codeChallenge,
        String codeChallengeMethod,
        Instant expiresAt) {

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }
}
