package com.example.oidc.authserver.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Strongly-typed binding for the {@code oidc.*} configuration block in application.yml.
 *
 * <p>Keeping these values in one place makes the issuer identifier and the token lifetimes
 * easy to reason about &mdash; they show up in the discovery document and in every minted token.
 */
@ConfigurationProperties(prefix = "oidc")
public class AuthServerProperties {

    /** The issuer identifier (e.g. {@code http://localhost:9000}); also the discovery base URL. */
    private String issuer = "http://localhost:9000";

    /** How long an authorization code is valid before it must be redeemed. Codes are single-use. */
    private long authorizationCodeTtlSeconds = 60;

    /** Access-token lifetime in seconds. */
    private long accessTokenTtlSeconds = 300;

    /** ID-token lifetime in seconds. */
    private long idTokenTtlSeconds = 300;

    /** Refresh-token lifetime in seconds. Much longer than the access token: its whole purpose is to
     *  outlive access tokens and mint replacements without re-prompting the user. */
    private long refreshTokenTtlSeconds = 3600;

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public long getAuthorizationCodeTtlSeconds() {
        return authorizationCodeTtlSeconds;
    }

    public void setAuthorizationCodeTtlSeconds(long authorizationCodeTtlSeconds) {
        this.authorizationCodeTtlSeconds = authorizationCodeTtlSeconds;
    }

    public long getAccessTokenTtlSeconds() {
        return accessTokenTtlSeconds;
    }

    public void setAccessTokenTtlSeconds(long accessTokenTtlSeconds) {
        this.accessTokenTtlSeconds = accessTokenTtlSeconds;
    }

    public long getIdTokenTtlSeconds() {
        return idTokenTtlSeconds;
    }

    public void setIdTokenTtlSeconds(long idTokenTtlSeconds) {
        this.idTokenTtlSeconds = idTokenTtlSeconds;
    }

    public long getRefreshTokenTtlSeconds() {
        return refreshTokenTtlSeconds;
    }

    public void setRefreshTokenTtlSeconds(long refreshTokenTtlSeconds) {
        this.refreshTokenTtlSeconds = refreshTokenTtlSeconds;
    }
}
