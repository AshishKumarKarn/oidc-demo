package com.example.oidc.authserver.service;

import com.example.oidc.authserver.config.AuthServerProperties;
import com.example.oidc.authserver.key.RsaKeyService;
import com.example.oidc.authserver.model.OidcUser;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Mints and signs the two JWTs the OP issues: the ID token and the access token.
 *
 * <p>Both are RS256-signed JWTs whose header carries the {@code kid} of {@link RsaKeyService}'s key
 * so that downstream parties can find the right public key in the JWK Set.
 *
 * <h3>ID token</h3>
 * Proves the user's identity to the <em>client</em>. {@code aud} = the client id. Carries identity
 * claims ({@code sub}, and {@code name}/{@code email} depending on scope) and the {@code nonce} from
 * the original request.
 *
 * <h3>Access token</h3>
 * Authorizes calls to the <em>resource server</em>. Here we model it as a JWT so the resource server
 * can validate it statelessly against the JWK Set. {@code aud} = {@code "resource-server"} and it
 * carries the granted {@code scope}.
 */
@Service
public class TokenService {

    private final RsaKeyService rsaKeyService;
    private final AuthServerProperties properties;

    /** The resource server's expected audience value; must match the resource-server config. */
    private static final String RESOURCE_SERVER_AUDIENCE = "resource-server";

    public TokenService(RsaKeyService rsaKeyService, AuthServerProperties properties) {
        this.rsaKeyService = rsaKeyService;
        this.properties = properties;
    }

    /**
     * Builds a signed ID token for the given user/client.
     *
     * @param user   the authenticated end user
     * @param clientId the client the token is for (becomes {@code aud})
     * @param scope  space-delimited granted scopes; controls which profile claims are added
     * @param nonce  the nonce from the authorization request (may be null); echoed back to bind the token
     */
    public String createIdToken(OidcUser user, String clientId, String scope, String nonce) {
        Instant now = Instant.now();
        Set<String> scopes = parseScopes(scope);

        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .issuer(properties.getIssuer())
                .subject(user.subject())
                .audience(clientId)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(properties.getIdTokenTtlSeconds())))
                // `auth_time` would be the actual authentication instant; we approximate with now.
                .claim("auth_time", now.getEpochSecond());

        if (nonce != null && !nonce.isBlank()) {
            // The client compares this against the nonce it generated, blocking ID-token replay.
            claims.claim("nonce", nonce);
        }
        // `profile` scope unlocks display-name claims; `email` scope unlocks the email claim.
        if (scopes.contains("profile")) {
            claims.claim("name", user.fullName());
            claims.claim("preferred_username", user.username());
        }
        if (scopes.contains("email")) {
            claims.claim("email", user.email());
            claims.claim("email_verified", true);
        }
        return sign(claims.build());
    }

    /**
     * Builds a signed access token authorizing API calls against the resource server.
     *
     * @param user  the resource owner
     * @param clientId the client that will present the token (recorded in the {@code client_id} claim)
     * @param scope space-delimited granted scopes; copied into the {@code scope} claim
     */
    public String createAccessToken(OidcUser user, String clientId, String scope) {
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(properties.getIssuer())
                .subject(user.subject())
                .audience(RESOURCE_SERVER_AUDIENCE)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(properties.getAccessTokenTtlSeconds())))
                .jwtID(UUID.randomUUID().toString())
                .claim("client_id", clientId)
                // The resource server authorizes individual endpoints based on this scope claim.
                .claim("scope", scope)
                .build();
        return sign(claims);
    }

    /** RS256-signs a claims set, stamping the active key's {@code kid} into the JWS header. */
    private String sign(JWTClaimsSet claims) {
        try {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(rsaKeyService.getRsaKey().getKeyID())
                    .type(com.nimbusds.jose.JOSEObjectType.JWT)
                    .build();
            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(new RSASSASigner(rsaKeyService.getRsaKey()));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Failed to sign JWT", e);
        }
    }

    private Set<String> parseScopes(String scope) {
        if (scope == null || scope.isBlank()) {
            return Set.of();
        }
        return Set.copyOf(List.of(scope.trim().split("\\s+")));
    }
}
