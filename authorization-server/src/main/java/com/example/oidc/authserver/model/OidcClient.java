package com.example.oidc.authserver.model;

import java.util.Set;

/**
 * A registered OAuth 2.0 / OIDC client (a.k.a. "relying party").
 *
 * <p>Before any flow can run, a client must be registered with the OP so the OP knows:
 * <ul>
 *   <li>its {@code clientId} / {@code clientSecret} (used to authenticate at the token endpoint),</li>
 *   <li>the exact {@code redirectUris} it is allowed to send the user back to (anti-phishing), and</li>
 *   <li>the {@code scopes} it may request.</li>
 * </ul>
 *
 * @param clientId      public identifier of the client
 * @param clientSecret  shared secret used for {@code client_secret_basic} / {@code client_secret_post} auth
 * @param redirectUris  the allow-list of redirect URIs; the {@code redirect_uri} parameter must match one exactly
 * @param scopes        scopes this client is permitted to request (e.g. {@code openid}, {@code profile}, {@code api.read})
 */
public record OidcClient(
        String clientId,
        String clientSecret,
        Set<String> redirectUris,
        Set<String> scopes) {

    /** @return true if the supplied redirect URI exactly matches a registered one. */
    public boolean isRedirectUriAllowed(String redirectUri) {
        return redirectUris.contains(redirectUri);
    }
}
