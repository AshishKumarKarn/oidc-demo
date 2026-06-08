package com.example.oidc.resourceserver.security;

import com.example.oidc.resourceserver.config.ResourceServerProperties;
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
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

import java.net.URL;
import java.util.Set;

/**
 * Validates incoming access-token JWTs against the OP's JWK Set.
 *
 * <p>The heavy lifting is configured once in {@link #init()} using Nimbus's {@link DefaultJWTProcessor}:
 * <ol>
 *   <li>A {@link RemoteJWKSet} fetches and caches the OP's public keys from {@code jwks-uri}. It
 *       transparently re-fetches when an unknown {@code kid} appears, so key rotation just works.</li>
 *   <li>A {@link JWSVerificationKeySelector} picks the RS256 key whose {@code kid} matches the
 *       token header, then verifies the signature.</li>
 *   <li>A {@link DefaultJWTClaimsVerifier} enforces the expected {@code iss} and {@code aud} and that
 *       {@code exp} is in the future (with a small clock-skew allowance).</li>
 * </ol>
 *
 * <p>On success the parsed, trusted {@link JWTClaimsSet} is returned; on any failure a
 * {@link TokenValidationException} is thrown.
 */
@Component
public class AccessTokenValidator {

    private final ResourceServerProperties properties;
    private ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

    public AccessTokenValidator(ResourceServerProperties properties) {
        this.properties = properties;
    }

    @PostConstruct
    void init() throws Exception {
        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();

        // 1. Remote, self-refreshing source of the OP's public signing keys.
        JWKSource<SecurityContext> keySource = new RemoteJWKSet<>(new URL(properties.getJwksUri()));

        // 2. Only accept RS256, and resolve the verification key by `kid` from the JWK Set.
        JWSKeySelector<SecurityContext> keySelector =
                new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, keySource);
        processor.setJWSKeySelector(keySelector);

        // 3. Enforce required claims: exact issuer + audience must be present, and exp must be valid.
        processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                // exact-match audience
                properties.getAudience(),
                // required claim values
                new JWTClaimsSet.Builder().issuer(properties.getIssuer()).build(),
                // claims that must simply be present
                Set.of("sub", "exp", "iat")));

        this.jwtProcessor = processor;
    }

    /**
     * Parses, verifies and claim-checks the token.
     *
     * @param token the raw compact JWT from the Authorization header
     * @return the trusted claim set
     * @throws TokenValidationException if signature, issuer, audience or expiry checks fail
     */
    public JWTClaimsSet validate(String token) {
        try {
            return jwtProcessor.process(token, null);
        } catch (Exception e) {
            throw new TokenValidationException(e.getMessage());
        }
    }

    /** Raised when a token cannot be trusted. Mapped to HTTP 401 by the filter. */
    public static class TokenValidationException extends RuntimeException {
        public TokenValidationException(String message) {
            super(message);
        }
    }
}
