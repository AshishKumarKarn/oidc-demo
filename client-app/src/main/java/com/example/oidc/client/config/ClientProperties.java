package com.example.oidc.client.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Binds the {@code oidc-client.*} configuration: our identity at the OP, what we request, and where
 * the protected API lives.
 */
@ConfigurationProperties(prefix = "oidc-client")
public class ClientProperties {

    /** Issuer of the OP we trust; the base for discovery. */
    private String issuer;

    /** Our client identifier, as registered at the OP. */
    private String clientId;

    /** Our client secret, used to authenticate at the token endpoint. */
    private String clientSecret;

    /** The redirect URI the OP will send the authorization code back to. Must be pre-registered. */
    private String redirectUri;

    /** Space-delimited scopes to request (must include {@code openid}). */
    private String scope;

    /** Base URL of the resource server we call with the access token. */
    private String resourceServerUrl;

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getResourceServerUrl() {
        return resourceServerUrl;
    }

    public void setResourceServerUrl(String resourceServerUrl) {
        this.resourceServerUrl = resourceServerUrl;
    }
}
