package com.example.oidc.client.service;

import com.example.oidc.client.config.ClientProperties;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * Fetches and caches the OP's discovery document so the client never has to hard-code endpoint URLs.
 *
 * <p>The document is retrieved from {@code <issuer>/.well-known/openid-configuration} on first use and
 * cached for the lifetime of the app. From it we extract the authorization, token, userinfo and JWKS
 * endpoints used throughout the flow.
 */
@Service
public class OidcDiscoveryService {

    private static final Logger log = LoggerFactory.getLogger(OidcDiscoveryService.class);

    private final ClientProperties properties;
    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final ObjectMapper objectMapper = new ObjectMapper();

    private volatile ProviderMetadata cached;

    public OidcDiscoveryService(ClientProperties properties) {
        this.properties = properties;
    }

    /** Returns the (lazily fetched, then cached) provider metadata. */
    public ProviderMetadata getMetadata() {
        if (cached == null) {
            synchronized (this) {
                if (cached == null) {
                    cached = fetch();
                }
            }
        }
        return cached;
    }

    private ProviderMetadata fetch() {
        String url = properties.getIssuer() + "/.well-known/openid-configuration";
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(url)).GET().build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new IllegalStateException("Discovery failed with HTTP " + response.statusCode());
            }
            JsonNode json = objectMapper.readTree(response.body());
            ProviderMetadata metadata = new ProviderMetadata(
                    json.get("issuer").asText(),
                    json.get("authorization_endpoint").asText(),
                    json.get("token_endpoint").asText(),
                    json.get("userinfo_endpoint").asText(),
                    json.get("jwks_uri").asText());
            log.info("Discovered OP metadata from {}", url);
            return metadata;
        } catch (Exception e) {
            throw new IllegalStateException("Unable to fetch OIDC discovery document from " + url, e);
        }
    }

    /** The subset of OpenID Provider Metadata this client uses. */
    public record ProviderMetadata(
            String issuer,
            String authorizationEndpoint,
            String tokenEndpoint,
            String userinfoEndpoint,
            String jwksUri) {
    }
}
