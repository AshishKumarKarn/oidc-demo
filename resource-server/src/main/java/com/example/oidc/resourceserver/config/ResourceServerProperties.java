package com.example.oidc.resourceserver.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Binds the {@code resource-server.*} configuration: which issuer to trust, where to fetch its
 * signing keys, and the audience this API expects in access tokens.
 */
@ConfigurationProperties(prefix = "resource-server")
public class ResourceServerProperties {

    /** Expected {@code iss} claim; tokens from any other issuer are rejected. */
    private String issuer;

    /** URL of the OP's JWK Set used to verify token signatures. */
    private String jwksUri;

    /** Expected {@code aud} claim for this API. */
    private String audience;

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getJwksUri() {
        return jwksUri;
    }

    public void setJwksUri(String jwksUri) {
        this.jwksUri = jwksUri;
    }

    public String getAudience() {
        return audience;
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }
}
