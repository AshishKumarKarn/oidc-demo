package com.example.oidc.authserver.store;

import com.example.oidc.authserver.model.AuthorizationCode;
import org.springframework.stereotype.Repository;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Short-lived store of issued authorization codes.
 *
 * <p>Codes are single-use: {@link #consume(String)} atomically removes and returns the record so a
 * replayed code cannot be exchanged twice. Expiry is enforced by the caller using
 * {@link AuthorizationCode#isExpired()}.
 */
@Repository
public class AuthorizationCodeStore {

    private final Map<String, AuthorizationCode> codes = new ConcurrentHashMap<>();

    public void save(AuthorizationCode code) {
        codes.put(code.code(), code);
    }

    /**
     * Atomically removes the code so it can never be redeemed a second time.
     *
     * @return the record if the code existed, otherwise empty.
     */
    public Optional<AuthorizationCode> consume(String code) {
        return Optional.ofNullable(codes.remove(code));
    }
}
