package com.example.oidc.client.service;

import com.example.oidc.client.config.ClientProperties;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.stereotype.Service;

import java.net.URL;
import java.util.Set;

/**
 * Validates the {@code id_token} returned from the token endpoint.
 *
 * <p>Per the OIDC spec, a client MUST validate the ID token before trusting it. This checks:
 * <ol>
 *   <li><b>Signature</b> &ndash; RS256, against the OP's JWK Set (key picked by {@code kid}).</li>
 *   <li><b>Issuer</b> ({@code iss}) &ndash; must equal the OP we trust.</li>
 *   <li><b>Audience</b> ({@code aud}) &ndash; must contain our {@code client_id}.</li>
 *   <li><b>Expiry</b> ({@code exp}) &ndash; must be in the future.</li>
 *   <li><b>Nonce</b> &ndash; must equal the nonce we generated for this login (replay protection).
 *       This is checked here explicitly because it is value-specific to each request.</li>
 * </ol>
 */
@Service
public class IdTokenValidator {

    private final ClientProperties properties;
    private final OidcDiscoveryService discoveryService;

    // Lazily built once the JWKS URI is known from discovery.
    private volatile ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

    public IdTokenValidator(ClientProperties properties, OidcDiscoveryService discoveryService) {
        this.properties = properties;
        this.discoveryService = discoveryService;
    }

    private ConfigurableJWTProcessor<SecurityContext> processor() throws Exception {
        if (jwtProcessor == null) {
            synchronized (this) {
                if (jwtProcessor == null) {
                    DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
                    JWKSource<SecurityContext> keySource =
                            new RemoteJWKSet<>(new URL(discoveryService.getMetadata().jwksUri()));
                    JWSKeySelector<SecurityContext> keySelector =
                            new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, keySource);
                    processor.setJWSKeySelector(keySelector);
                    // Enforce issuer + audience (our client id) and presence of the core claims.
                    processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                            properties.getClientId(),
                            new JWTClaimsSet.Builder().issuer(properties.getIssuer()).build(),
                            Set.of("sub", "exp", "iat")));
                    jwtProcessor = processor;
                }
            }
        }
        return jwtProcessor;
    }

    /**
     * Validates the token and the expected nonce.
     *
     * @param idToken       the compact JWT from the token response
     * @param expectedNonce the nonce generated at /login and stored in the session
     * @return the trusted claim set
     * @throws IdTokenValidationException on any failure
     */
    public JWTClaimsSet validate(String idToken, String expectedNonce) {
        try {
            JWTClaimsSet claims = processor().process(idToken, null);

            // Nonce binding: the ID token must echo the nonce we sent, or it could be a replay.
            String tokenNonce = claims.getStringClaim("nonce");
            if (expectedNonce != null && !expectedNonce.equals(tokenNonce)) {
                throw new IdTokenValidationException("nonce mismatch");
            }
            return claims;
        } catch (IdTokenValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new IdTokenValidationException(e.getMessage());
        }
    }

    /** Raised when the ID token cannot be trusted. */
    public static class IdTokenValidationException extends RuntimeException {
        public IdTokenValidationException(String message) {
            super(message);
        }
    }
}
