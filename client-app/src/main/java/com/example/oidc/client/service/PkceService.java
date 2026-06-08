package com.example.oidc.client.service;

import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Generates PKCE (RFC 7636) parameters on the client side.
 *
 * <p>The flow:
 * <ol>
 *   <li>{@link #createPair()} generates a high-entropy random {@code code_verifier} and derives the
 *       {@code code_challenge = BASE64URL(SHA-256(verifier))}.</li>
 *   <li>The challenge is sent on the authorization request; the verifier is kept secret in the session.</li>
 *   <li>At the token request the verifier is sent so the OP can prove it matches the earlier challenge.</li>
 * </ol>
 * This binds the authorization code to this client instance, so an intercepted code is useless.
 */
@Service
public class PkceService {

    private static final SecureRandom RANDOM = new SecureRandom();

    /** Always use S256 in practice; advertised on the authorization request. */
    public static final String METHOD = "S256";

    /** Creates a fresh verifier/challenge pair for one login attempt. */
    public PkcePair createPair() {
        String verifier = generateVerifier();
        String challenge = deriveChallenge(verifier);
        return new PkcePair(verifier, challenge);
    }

    /** 32 random bytes, base64url-encoded -> a 43-char verifier (well within the 43..128 range). */
    private String generateVerifier() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String deriveChallenge(String verifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** A verifier (kept secret) and its derived challenge (sent to the OP). */
    public record PkcePair(String verifier, String challenge) {
    }
}
