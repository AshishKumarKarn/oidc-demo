package com.example.oidc.authserver.service;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * Implements PKCE (Proof Key for Code Exchange, RFC 7636) verification.
 *
 * <p>PKCE defends the authorization-code flow against code interception. At the authorization
 * request the client sends a {@code code_challenge} (the hashed secret). At the token request it
 * sends the original {@code code_verifier}. The OP recomputes the challenge from the verifier and
 * checks it matches what was stored with the code &mdash; proving the same party that started the
 * flow is finishing it.
 *
 * <p>Two methods are supported:
 * <ul>
 *   <li>{@code S256}: challenge = BASE64URL(SHA-256(verifier)) &mdash; the only method that should
 *       be used in practice.</li>
 *   <li>{@code plain}: challenge == verifier &mdash; supported for completeness only.</li>
 * </ul>
 */
@Component
public class PkceValidator {

    /**
     * @param codeVerifier  the verifier presented at the token endpoint
     * @param storedChallenge the challenge captured at the authorization endpoint
     * @param method        {@code "S256"} or {@code "plain"} (null/blank treated as plain)
     * @return true if the verifier proves knowledge of the secret behind the challenge
     */
    public boolean verify(String codeVerifier, String storedChallenge, String method) {
        if (codeVerifier == null || storedChallenge == null) {
            return false;
        }
        if (method == null || method.isBlank() || method.equalsIgnoreCase("plain")) {
            // plain: the challenge is the verifier verbatim.
            return constantTimeEquals(codeVerifier, storedChallenge);
        }
        if (method.equalsIgnoreCase("S256")) {
            String computed = sha256Base64Url(codeVerifier);
            return constantTimeEquals(computed, storedChallenge);
        }
        // Unknown method -> reject.
        return false;
    }

    /** challenge = BASE64URL-ENCODE(SHA-256(ASCII(code_verifier))), no padding. */
    private String sha256Base64Url(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    /** Length-constant comparison to avoid leaking match progress via timing. */
    private boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8));
    }
}
