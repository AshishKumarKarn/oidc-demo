package com.example.oidc.authserver.model;

/**
 * An end user that can authenticate at the OP.
 *
 * <p>The {@code subject} is the stable, unique identifier for the user and becomes the {@code sub}
 * claim in the ID token. The remaining fields are sample "profile" / "email" claims returned in the
 * ID token and from the UserInfo endpoint depending on the granted scopes.
 *
 * <p>NOTE: passwords are stored in plain text here purely for demo readability. A real OP must store
 * only a salted hash (bcrypt/argon2) and compare against it.
 *
 * @param subject  stable unique id -> ID token `sub`
 * @param username login name typed on the login form
 * @param password plain-text password (demo only!)
 * @param fullName display name -> `name` claim (profile scope)
 * @param email    email address -> `email` claim (email scope)
 */
public record OidcUser(
        String subject,
        String username,
        String password,
        String fullName,
        String email) {
}
