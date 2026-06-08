package com.example.oidc.authserver.key;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.UUID;

/**
 * Holds the RSA key pair used to sign tokens, and exposes the public half as a JWK Set.
 *
 * <p>In a real OP the private key would live in an HSM or a securely-managed keystore and would
 * be rotated periodically. For this demo we generate a fresh 2048-bit RSA key on every startup.
 * The key carries a random {@code kid} (key id) so that:
 * <ul>
 *   <li>the {@code kid} is written into the JWS header of every token we sign, and</li>
 *   <li>relying parties / resource servers can look up the matching public key in the JWK Set.</li>
 * </ul>
 */
@Service
public class RsaKeyService {

    private static final Logger log = LoggerFactory.getLogger(RsaKeyService.class);

    /** The full RSA key (public + private). Never leaves this server. */
    private RSAKey rsaKey;

    @PostConstruct
    void generateKey() {
        try {
            // The key id ties a token's signature to a specific public key in the JWK Set.
            String keyId = UUID.randomUUID().toString();
            this.rsaKey = new RSAKeyGenerator(2048)
                    .keyID(keyId)
                    .generate();
            log.info("Generated RSA signing key with kid={}", keyId);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to generate RSA signing key", e);
        }
    }

    /** @return the full key pair, used by {@link com.example.oidc.authserver.service.TokenService} to sign. */
    public RSAKey getRsaKey() {
        return rsaKey;
    }

    /**
     * Builds the JWK Set document served at {@code /.well-known/jwks.json}.
     *
     * <p>{@link RSAKey#toPublicJWK()} strips the private key material, so only the public modulus
     * and exponent (plus {@code kid}, {@code kty}, {@code use}) are exposed.
     */
    public Map<String, Object> jwkSet() {
        JWKSet publicSet = new JWKSet(rsaKey.toPublicJWK());
        // `false` => public parameters only; this is the exact JSON clients expect.
        return publicSet.toJSONObject(false);
    }
}
