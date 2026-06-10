package com.example.oidc.client.service;

import com.example.oidc.client.config.ClientProperties;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Performs the back-channel calls to the OP's token endpoint.
 *
 * <p>This is the confidential half of the flow: it runs server-to-server (never in the browser) and
 * authenticates the client with HTTP Basic ({@code client_secret_basic}). It handles two grants:
 * <ul>
 *   <li>{@link #exchangeCode} &mdash; redeem an authorization code (with the PKCE verifier) for the
 *       first set of tokens;</li>
 *   <li>{@link #refresh} &mdash; trade a refresh token for a fresh access token (and a rotated refresh
 *       token) when the access token has expired, without re-prompting the user.</li>
 * </ul>
 */
@Service
public class TokenClient {

    private static final Logger log = LoggerFactory.getLogger(TokenClient.class);

    private final ClientProperties properties;
    private final OidcDiscoveryService discoveryService;
    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public TokenClient(ClientProperties properties, OidcDiscoveryService discoveryService) {
        this.properties = properties;
        this.discoveryService = discoveryService;
    }

    /**
     * Exchanges an authorization code for tokens.
     *
     * @param code         the code received on the callback
     * @param codeVerifier the PKCE verifier generated at /login (proves we started the flow)
     * @return the parsed token response (includes a refresh token)
     * @throws TokenExchangeException if the OP returns an error
     */
    public TokenResponse exchangeCode(String code, String codeVerifier) {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "authorization_code");
        form.put("code", code);
        form.put("redirect_uri", properties.getRedirectUri());
        form.put("code_verifier", codeVerifier);
        return post(form);
    }

    /**
     * Trades a refresh token for a fresh set of tokens.
     *
     * <p>Used when the access token has expired. The OP rotates the refresh token, so the response
     * carries a <em>new</em> refresh token that the caller must store in place of the old one.
     *
     * @param refreshToken the current refresh token
     * @return the parsed token response (with a new access token and a new refresh token)
     * @throws TokenExchangeException if the refresh token is invalid/expired
     */
    public TokenResponse refresh(String refreshToken) {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "refresh_token");
        form.put("refresh_token", refreshToken);
        return post(form);
    }

    /** Shared back-channel POST: client_secret_basic auth, urlencoded body, JSON parse. */
    private TokenResponse post(Map<String, String> form) {
        String tokenEndpoint = discoveryService.getMetadata().tokenEndpoint();
        String body = urlEncode(form);

        // client_secret_basic: Authorization: Basic base64(clientId:clientSecret)
        String basic = Base64.getEncoder().encodeToString(
                (properties.getClientId() + ":" + properties.getClientSecret())
                        .getBytes(StandardCharsets.UTF_8));

        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(tokenEndpoint))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Authorization", "Basic " + basic)
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            JsonNode json = objectMapper.readTree(response.body());

            if (response.statusCode() != 200) {
                String error = json.has("error") ? json.get("error").asText() : "unknown_error";
                String description = json.has("error_description") ? json.get("error_description").asText() : "";
                throw new TokenExchangeException(error + ": " + description);
            }

            log.debug("Token request ({}) succeeded", form.get("grant_type"));
            return new TokenResponse(
                    json.get("access_token").asText(),
                    json.has("id_token") ? json.get("id_token").asText() : null,
                    json.has("refresh_token") ? json.get("refresh_token").asText() : null,
                    json.has("token_type") ? json.get("token_type").asText() : "Bearer",
                    json.has("scope") ? json.get("scope").asText() : "",
                    json.has("expires_in") ? json.get("expires_in").asInt() : 0);
        } catch (TokenExchangeException e) {
            throw e;
        } catch (Exception e) {
            throw new TokenExchangeException("Token request failed: " + e.getMessage());
        }
    }

    private String urlEncode(Map<String, String> form) {
        return form.entrySet().stream()
                .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "="
                        + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
    }

    /** The successful token-endpoint response. {@code idToken}/{@code refreshToken} may be null. */
    public record TokenResponse(
            String accessToken,
            String idToken,
            String refreshToken,
            String tokenType,
            String scope,
            int expiresIn) {
    }

    /** Raised when the OP rejects the token request. */
    public static class TokenExchangeException extends RuntimeException {
        public TokenExchangeException(String message) {
            super(message);
        }
    }
}
