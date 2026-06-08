package com.example.oidc.authserver.web;

import com.example.oidc.authserver.config.AuthServerProperties;
import com.example.oidc.authserver.model.AuthorizationCode;
import com.example.oidc.authserver.model.OidcClient;
import com.example.oidc.authserver.model.OidcUser;
import com.example.oidc.authserver.store.AuthorizationCodeStore;
import com.example.oidc.authserver.store.ClientRegistry;
import com.example.oidc.authserver.store.UserRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.servlet.view.RedirectView;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Implements the OIDC <b>authorization endpoint</b> and the login form that backs it.
 *
 * <p>Flow:
 * <ol>
 *   <li>{@code GET /authorize} &ndash; the client redirects the user's browser here with the
 *       authorization request parameters. We validate them and render a login page. The parameters
 *       are carried forward as hidden form fields so they survive the login POST.</li>
 *   <li>{@code POST /login} &ndash; the user submits credentials. On success we generate a one-time
 *       authorization code bound to all the request context (incl. the PKCE challenge and nonce) and
 *       302-redirect the browser back to the client's {@code redirect_uri} with {@code code} and
 *       {@code state}.</li>
 * </ol>
 */
@Controller
public class AuthorizationController {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationController.class);

    private final ClientRegistry clientRegistry;
    private final UserRegistry userRegistry;
    private final AuthorizationCodeStore codeStore;
    private final AuthServerProperties properties;

    public AuthorizationController(ClientRegistry clientRegistry,
                                   UserRegistry userRegistry,
                                   AuthorizationCodeStore codeStore,
                                   AuthServerProperties properties) {
        this.clientRegistry = clientRegistry;
        this.userRegistry = userRegistry;
        this.codeStore = codeStore;
        this.properties = properties;
    }

    /**
     * Authorization endpoint. Validates the request and shows the login page.
     *
     * <p>Per OAuth 2.0, if {@code client_id} or {@code redirect_uri} are invalid we must NOT redirect
     * (that could aid an attacker); instead we fail with an error page. All other validation errors
     * are redirected back to the client as {@code error} responses.
     */
    @GetMapping("/authorize")
    public Object authorize(
            @RequestParam("response_type") String responseType,
            @RequestParam("client_id") String clientId,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam(value = "scope", defaultValue = "") String scope,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam(value = "nonce", required = false) String nonce,
            @RequestParam(value = "code_challenge", required = false) String codeChallenge,
            @RequestParam(value = "code_challenge_method", required = false) String codeChallengeMethod,
            Model model) {

        // 1. The client must be registered.
        Optional<OidcClient> maybeClient = clientRegistry.findByClientId(clientId);
        if (maybeClient.isEmpty()) {
            throw new InvalidRequestException("Unknown client_id: " + clientId);
        }
        OidcClient client = maybeClient.get();

        // 2. The redirect URI must exactly match a registered one (anti open-redirect).
        if (!client.isRedirectUriAllowed(redirectUri)) {
            throw new InvalidRequestException("redirect_uri not registered for this client");
        }

        // From here on, errors are safe to send back to the (validated) redirect_uri.
        // 3. This demo OP only supports the authorization code flow.
        if (!"code".equals(responseType)) {
            return errorRedirect(redirectUri, "unsupported_response_type",
                    "Only response_type=code is supported", state);
        }
        // 4. OIDC requires the `openid` scope.
        if (!scope.contains("openid")) {
            return errorRedirect(redirectUri, "invalid_scope",
                    "The 'openid' scope is required", state);
        }
        // 5. We require PKCE (S256 recommended). Reject requests without a challenge.
        if (codeChallenge == null || codeChallenge.isBlank()) {
            return errorRedirect(redirectUri, "invalid_request",
                    "PKCE code_challenge is required", state);
        }

        // Valid request -> render login, carrying every parameter as hidden fields.
        model.addAttribute("clientId", clientId);
        model.addAttribute("redirectUri", redirectUri);
        model.addAttribute("scope", scope);
        model.addAttribute("state", state == null ? "" : state);
        model.addAttribute("nonce", nonce == null ? "" : nonce);
        model.addAttribute("codeChallenge", codeChallenge);
        model.addAttribute("codeChallengeMethod",
                codeChallengeMethod == null ? "plain" : codeChallengeMethod);
        model.addAttribute("error", null);
        return "login";
    }

    /**
     * Processes the login form. On success issues an authorization code and redirects back to the client.
     */
    @PostMapping("/login")
    public Object login(
            @RequestParam("username") String username,
            @RequestParam("password") String password,
            @RequestParam("client_id") String clientId,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam("scope") String scope,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam(value = "nonce", required = false) String nonce,
            @RequestParam("code_challenge") String codeChallenge,
            @RequestParam("code_challenge_method") String codeChallengeMethod,
            Model model) {

        Optional<OidcUser> maybeUser = userRegistry.authenticate(username, password);
        if (maybeUser.isEmpty()) {
            // Re-show the form (with all hidden fields intact) and an error message.
            model.addAttribute("clientId", clientId);
            model.addAttribute("redirectUri", redirectUri);
            model.addAttribute("scope", scope);
            model.addAttribute("state", state == null ? "" : state);
            model.addAttribute("nonce", nonce == null ? "" : nonce);
            model.addAttribute("codeChallenge", codeChallenge);
            model.addAttribute("codeChallengeMethod", codeChallengeMethod);
            model.addAttribute("error", "Invalid username or password");
            return "login";
        }

        OidcUser user = maybeUser.get();

        // Generate an opaque, single-use code and bind the full request context to it server-side.
        String code = UUID.randomUUID().toString().replace("-", "");
        AuthorizationCode authCode = new AuthorizationCode(
                code,
                user.subject(),
                clientId,
                redirectUri,
                scope,
                nonce,
                codeChallenge,
                codeChallengeMethod,
                Instant.now().plusSeconds(properties.getAuthorizationCodeTtlSeconds()));
        codeStore.save(authCode);
        log.debug("Issued authorization code for user={} client={}", user.username(), clientId);

        // Redirect the browser back to the client with the code (and the state, unchanged).
        StringBuilder target = new StringBuilder(redirectUri)
                .append("?code=").append(urlEncode(code));
        if (state != null && !state.isBlank()) {
            target.append("&state=").append(urlEncode(state));
        }
        return new RedirectView(target.toString());
    }

    /** Builds a spec-compliant error redirect back to the client. */
    private RedirectView errorRedirect(String redirectUri, String error, String description, String state) {
        StringBuilder target = new StringBuilder(redirectUri)
                .append("?error=").append(urlEncode(error))
                .append("&error_description=").append(urlEncode(description));
        if (state != null && !state.isBlank()) {
            target.append("&state=").append(urlEncode(state));
        }
        return new RedirectView(target.toString());
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    /** Thrown for client/redirect_uri problems that must surface as an error page, not a redirect. */
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    static class InvalidRequestException extends RuntimeException {
        InvalidRequestException(String message) {
            super(message);
        }
    }
}
