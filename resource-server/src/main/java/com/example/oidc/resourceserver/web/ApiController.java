package com.example.oidc.resourceserver.web;

import com.example.oidc.resourceserver.security.AuthenticatedToken;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * The protected API. Every method here runs only after {@code BearerTokenAuthenticationFilter} has
 * validated the access token and attached an {@link AuthenticatedToken} to the request.
 *
 * <p>This controller additionally demonstrates <b>scope-based authorization</b>: the
 * {@code /api/messages} endpoint requires the {@code api.read} scope, returning 403 otherwise, while
 * {@code /api/me} only needs a valid token.
 */
@RestController
@RequestMapping("/api")
public class ApiController {

    /** Returns information about the caller, derived purely from the validated token. */
    @GetMapping("/me")
    public Map<String, Object> me(HttpServletRequest request) {
        AuthenticatedToken token = currentToken(request);
        return Map.of(
                "subject", token.getSubject(),
                "clientId", token.getClientId(),
                "scopes", token.getScopes());
    }

    /** Returns sample protected data; requires the {@code api.read} scope. */
    @GetMapping("/messages")
    public ResponseEntity<?> messages(HttpServletRequest request) {
        AuthenticatedToken token = currentToken(request);

        // Enforce fine-grained authorization from the token's granted scopes.
        if (!token.hasScope("api.read")) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of(
                            "error", "insufficient_scope",
                            "error_description", "This endpoint requires the 'api.read' scope",
                            "required_scope", "api.read"));
        }

        List<Map<String, Object>> messages = List.of(
                Map.of("id", 1, "from", "system", "text", "Welcome, your token is valid!"),
                Map.of("id", 2, "from", "system", "text", "This data is protected by an access token."));
        return ResponseEntity.ok(Map.of(
                "servedAt", Instant.now().toString(),
                "owner", token.getSubject(),
                "messages", messages));
    }

    /** Convenience accessor for the token the filter placed on the request. */
    private AuthenticatedToken currentToken(HttpServletRequest request) {
        return (AuthenticatedToken) request.getAttribute(AuthenticatedToken.REQUEST_ATTRIBUTE);
    }
}
