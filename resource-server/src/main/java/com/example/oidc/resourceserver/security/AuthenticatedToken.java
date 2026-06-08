package com.example.oidc.resourceserver.security;

import com.nimbusds.jwt.JWTClaimsSet;

import java.text.ParseException;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * A thin, read-only view over a validated access token, exposing just what the API needs:
 * the subject, the client id, and the granted scopes.
 *
 * <p>An instance is placed on the request (see {@link BearerTokenAuthenticationFilter}) once the
 * token has been validated, so controllers can make authorization decisions without re-parsing JWTs.
 */
public class AuthenticatedToken {

    /** Request attribute key under which the filter stores the authenticated token. */
    public static final String REQUEST_ATTRIBUTE = "authenticatedToken";

    private final String subject;
    private final String clientId;
    private final Set<String> scopes;

    private AuthenticatedToken(String subject, String clientId, Set<String> scopes) {
        this.subject = subject;
        this.clientId = clientId;
        this.scopes = scopes;
    }

    /** Builds an {@link AuthenticatedToken} from a verified claim set. */
    public static AuthenticatedToken fromClaims(JWTClaimsSet claims) throws ParseException {
        String scopeClaim = claims.getStringClaim("scope");
        Set<String> scopes = (scopeClaim == null || scopeClaim.isBlank())
                ? Set.of()
                : Arrays.stream(scopeClaim.trim().split("\\s+")).collect(Collectors.toUnmodifiableSet());
        return new AuthenticatedToken(claims.getSubject(), claims.getStringClaim("client_id"), scopes);
    }

    public String getSubject() {
        return subject;
    }

    public String getClientId() {
        return clientId;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    /** @return true if the token was granted the given scope. */
    public boolean hasScope(String scope) {
        return scopes.contains(scope);
    }
}
