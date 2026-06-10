package com.example.oidc.authserver.store;

import com.example.oidc.authserver.model.RefreshToken;
import org.springframework.stereotype.Repository;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Server-side store of issued refresh tokens.
 *
 * <p>This is the OP's one piece of genuinely long-lived, stateful security data. Holding it server-side
 * (here, an in-memory map; a real OP would use a database) is what gives the OP powers that stateless
 * JWTs cannot provide: <b>rotation</b> and <b>revocation</b>.
 *
 * <p>{@link #consume(String)} removes a token as it is redeemed, so each refresh token is single-use —
 * the caller immediately issues a replacement. This <em>rotation</em> means a leaked-and-replayed token
 * is detectable: the second use finds nothing.
 */
@Repository
public class RefreshTokenStore {

    private final Map<String, RefreshToken> tokens = new ConcurrentHashMap<>();
    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Mints, stores, and returns a new opaque refresh token bound to the given context.
     *
     * @param ttlSeconds lifetime of the new token
     */
    public RefreshToken issue(String subject, String clientId, String scope, String nonce, long ttlSeconds) {
        byte[] raw = new byte[32];
        secureRandom.nextBytes(raw);
        String value = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        RefreshToken token = new RefreshToken(
                value, subject, clientId, scope, nonce, Instant.now().plusSeconds(ttlSeconds));
        tokens.put(value, token);
        return token;
    }

    /**
     * Atomically removes and returns the token, enforcing single-use (rotation).
     *
     * @return the record if the token existed, otherwise empty.
     */
    public Optional<RefreshToken> consume(String value) {
        return Optional.ofNullable(tokens.remove(value));
    }
}
