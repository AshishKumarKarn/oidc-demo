package com.example.oidc.authserver.web;

import com.example.oidc.authserver.config.AuthServerProperties;
import com.example.oidc.authserver.key.RsaKeyService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Serves the two metadata documents that let clients and resource servers self-configure:
 *
 * <ul>
 *   <li>{@code GET /.well-known/openid-configuration} &ndash; the OpenID Provider Metadata
 *       (RFC 8414 / OIDC Discovery). A client fetches this once to learn every endpoint URL and
 *       the provider's capabilities, instead of hard-coding them.</li>
 *   <li>{@code GET /.well-known/jwks.json} &ndash; the JSON Web Key Set holding the public signing
 *       key(s). Anyone validating a token fetches this to verify the RS256 signature.</li>
 * </ul>
 */
@RestController
public class DiscoveryController {

    private final AuthServerProperties properties;
    private final RsaKeyService rsaKeyService;

    public DiscoveryController(AuthServerProperties properties, RsaKeyService rsaKeyService) {
        this.properties = properties;
        this.rsaKeyService = rsaKeyService;
    }

    /**
     * The discovery document. Every URL is derived from the configured issuer so there is a single
     * source of truth. We advertise only what this demo OP actually supports.
     */
    @GetMapping("/.well-known/openid-configuration")
    public Map<String, Object> openidConfiguration() {
        String issuer = properties.getIssuer();
        return Map.ofEntries(
                Map.entry("issuer", issuer),
                Map.entry("authorization_endpoint", issuer + "/authorize"),
                Map.entry("token_endpoint", issuer + "/token"),
                Map.entry("userinfo_endpoint", issuer + "/userinfo"),
                Map.entry("jwks_uri", issuer + "/.well-known/jwks.json"),
                Map.entry("response_types_supported", List.of("code")),
                Map.entry("grant_types_supported", List.of("authorization_code", "refresh_token")),
                Map.entry("subject_types_supported", List.of("public")),
                Map.entry("id_token_signing_alg_values_supported", List.of("RS256")),
                Map.entry("scopes_supported", List.of("openid", "profile", "email", "api.read")),
                Map.entry("token_endpoint_auth_methods_supported",
                        List.of("client_secret_basic", "client_secret_post")),
                Map.entry("code_challenge_methods_supported", List.of("S256", "plain")),
                Map.entry("claims_supported",
                        List.of("sub", "iss", "aud", "exp", "iat", "nonce", "auth_time",
                                "name", "preferred_username", "email", "email_verified")));
    }

    /** Public JWK Set used to verify token signatures. */
    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> jwks() {
        return rsaKeyService.jwkSet();
    }
}
