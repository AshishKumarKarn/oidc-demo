package com.example.oidc.client.service;

import com.example.oidc.client.config.ClientProperties;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * Calls the protected resource server, presenting the access token as a Bearer credential.
 *
 * <p>This demonstrates the whole point of the flow: the client uses the {@code access_token} it
 * obtained to consume an API on the user's behalf, without ever handling the user's password.
 */
@Service
public class ResourceServerClient {

    private final ClientProperties properties;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    public ResourceServerClient(ClientProperties properties) {
        this.properties = properties;
    }

    /**
     * GETs a path on the resource server with the access token attached.
     *
     * @param path        e.g. {@code /api/messages}
     * @param accessToken the bearer token obtained from the OP
     * @return the raw response body (JSON) and status, wrapped for display
     */
    public ApiResult get(String path, String accessToken) {
        String url = properties.getResourceServerUrl() + path;
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                    .header("Authorization", "Bearer " + accessToken)
                    .header("Accept", "application/json")
                    .GET()
                    .build();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            return new ApiResult(response.statusCode(), response.body());
        } catch (Exception e) {
            return new ApiResult(0, "Call failed: " + e.getMessage());
        }
    }

    /** A resource-server response: HTTP status + raw body. */
    public record ApiResult(int status, String body) {
    }
}
