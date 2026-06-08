package com.example.oidc.authserver.store;

import com.example.oidc.authserver.model.OidcUser;
import org.springframework.stereotype.Repository;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory user directory.
 *
 * <p>Seeds a couple of demo accounts. Credentials are validated by {@link #authenticate(String, String)}.
 * Lookup by {@code subject} is used when minting tokens for an already-authenticated user.
 */
@Repository
public class UserRegistry {

    private final Map<String, OidcUser> usersByUsername = new ConcurrentHashMap<>();
    private final Map<String, OidcUser> usersBySubject = new ConcurrentHashMap<>();

    public UserRegistry() {
        register(new OidcUser("user-001", "alice", "password", "Alice Anderson", "alice@example.com"));
        register(new OidcUser("user-002", "bob", "password", "Bob Brown", "bob@example.com"));
    }

    private void register(OidcUser user) {
        usersByUsername.put(user.username(), user);
        usersBySubject.put(user.subject(), user);
    }

    /**
     * Verifies the login form credentials.
     *
     * @return the matching user, or empty if the username is unknown or the password is wrong.
     */
    public Optional<OidcUser> authenticate(String username, String password) {
        OidcUser user = usersByUsername.get(username);
        if (user != null && user.password().equals(password)) {
            return Optional.of(user);
        }
        return Optional.empty();
    }

    public Optional<OidcUser> findBySubject(String subject) {
        return Optional.ofNullable(usersBySubject.get(subject));
    }
}
