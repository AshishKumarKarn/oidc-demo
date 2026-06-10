package com.example.oidc.authserver.model;

import java.time.Instant;

/**
 * A server-side refresh token record.
 *
 * <p>Unlike the access and ID tokens (which are stateless, self-contained JWTs), a refresh token is an
 * <b>opaque random string</b> whose meaning lives entirely in this record on the server. That is what
 * makes it <em>revocable</em>: deleting the record invalidates the token immediately, with no waiting
 * for an {@code exp} claim to pass. The record binds the token to the user, the client it was issued
 * to, the granted scope, and the original {@code nonce} (so a refreshed ID token can echo it).
 *
 * @param token     the opaque token value presented by the client
 * @param subject   the user the token acts for
 * @param clientId  the client the token was issued to (a token may only be used by that client)
 * @param scope     the space-delimited scope the refreshed tokens carry
 * @param nonce     the original authentication nonce, or {@code null}
 * @param expiresAt absolute expiry instant
 */
public record RefreshToken(String token, String subject, String clientId, String scope,
                           String nonce, Instant expiresAt) {

    /** @return true if this token is past its expiry. */
    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }
}
