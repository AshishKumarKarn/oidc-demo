package com.example.oidc.client.web;

import com.example.oidc.client.config.ClientProperties;
import com.example.oidc.client.service.IdTokenValidator;
import com.example.oidc.client.service.OidcDiscoveryService;
import com.example.oidc.client.service.PkceService;
import com.example.oidc.client.service.ResourceServerClient;
import com.example.oidc.client.service.TokenClient;
import com.nimbusds.jwt.JWTClaimsSet;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.view.RedirectView;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Drives the Authorization Code + PKCE flow from the client's side and renders the UI.
 *
 * <p>Session keys used to carry per-login state between {@code /login} and {@code /callback}:
 * {@code state}, {@code nonce} and the PKCE {@code code_verifier}. After a successful callback the
 * tokens and identity claims are stored in the session to represent a logged-in user.
 */
@Controller
public class LoginController {

    private static final Logger log = LoggerFactory.getLogger(LoginController.class);

    // Session attribute keys.
    private static final String SESSION_STATE = "oidc_state";
    private static final String SESSION_NONCE = "oidc_nonce";
    private static final String SESSION_CODE_VERIFIER = "oidc_code_verifier";
    private static final String SESSION_CLAIMS = "oidc_claims";
    private static final String SESSION_ACCESS_TOKEN = "oidc_access_token";
    private static final String SESSION_ID_TOKEN = "oidc_id_token";
    private static final String SESSION_REFRESH_TOKEN = "oidc_refresh_token";

    private final ClientProperties properties;
    private final OidcDiscoveryService discoveryService;
    private final PkceService pkceService;
    private final TokenClient tokenClient;
    private final IdTokenValidator idTokenValidator;
    private final ResourceServerClient resourceServerClient;

    public LoginController(ClientProperties properties,
                           OidcDiscoveryService discoveryService,
                           PkceService pkceService,
                           TokenClient tokenClient,
                           IdTokenValidator idTokenValidator,
                           ResourceServerClient resourceServerClient) {
        this.properties = properties;
        this.discoveryService = discoveryService;
        this.pkceService = pkceService;
        this.tokenClient = tokenClient;
        this.idTokenValidator = idTokenValidator;
        this.resourceServerClient = resourceServerClient;
    }

    /** Home page. Shows a login button, or a link to the profile if already signed in. */
    @GetMapping("/")
    public String home(HttpSession session, Model model) {
        model.addAttribute("loggedIn", session.getAttribute(SESSION_CLAIMS) != null);
        model.addAttribute("issuer", properties.getIssuer());
        return "index";
    }

    /**
     * Step 1 &mdash; build the authorization request and redirect the browser to the OP.
     *
     * <p>We generate three secrets and stash them in the session:
     * <ul>
     *   <li>{@code state} &ndash; CSRF protection; echoed back and compared on the callback,</li>
     *   <li>{@code nonce} &ndash; replay protection; embedded in and checked against the ID token,</li>
     *   <li>PKCE {@code code_verifier} &ndash; only its hash (challenge) is sent now.</li>
     * </ul>
     */
    @GetMapping("/login")
    public RedirectView login(HttpSession session) {
        String authorizationEndpoint = discoveryService.getMetadata().authorizationEndpoint();

        String state = UUID.randomUUID().toString();
        String nonce = UUID.randomUUID().toString();
        PkceService.PkcePair pkce = pkceService.createPair();

        session.setAttribute(SESSION_STATE, state);
        session.setAttribute(SESSION_NONCE, nonce);
        session.setAttribute(SESSION_CODE_VERIFIER, pkce.verifier());

        Map<String, String> params = new LinkedHashMap<>();
        params.put("response_type", "code");
        params.put("client_id", properties.getClientId());
        params.put("redirect_uri", properties.getRedirectUri());
        params.put("scope", properties.getScope());
        params.put("state", state);
        params.put("nonce", nonce);
        params.put("code_challenge", pkce.challenge());
        params.put("code_challenge_method", PkceService.METHOD);

        String url = authorizationEndpoint + "?" + toQuery(params);
        log.debug("Redirecting to authorization endpoint: {}", url);
        return new RedirectView(url);
    }

    /**
     * Step 2 &mdash; the OP redirects back here with {@code code} + {@code state} (or an {@code error}).
     *
     * <p>We verify state (CSRF), exchange the code for tokens (sending the PKCE verifier), validate
     * the ID token (signature, iss, aud, exp, nonce), then persist the session and call the API.
     */
    @GetMapping("/callback")
    public Object callback(
            @RequestParam(value = "code", required = false) String code,
            @RequestParam(value = "state", required = false) String state,
            @RequestParam(value = "error", required = false) String error,
            @RequestParam(value = "error_description", required = false) String errorDescription,
            HttpSession session,
            Model model) {

        // The OP signalled an error instead of issuing a code.
        if (error != null) {
            model.addAttribute("error", error);
            model.addAttribute("errorDescription", errorDescription);
            return "error";
        }

        // CSRF check: the returned state must equal the one we generated.
        String expectedState = (String) session.getAttribute(SESSION_STATE);
        if (expectedState == null || !expectedState.equals(state)) {
            model.addAttribute("error", "invalid_state");
            model.addAttribute("errorDescription", "State mismatch &ndash; possible CSRF. Please retry login.");
            return "error";
        }

        try {
            String codeVerifier = (String) session.getAttribute(SESSION_CODE_VERIFIER);
            String expectedNonce = (String) session.getAttribute(SESSION_NONCE);

            // Exchange the code (confidential, server-to-server) and validate the returned ID token.
            TokenClient.TokenResponse tokens = tokenClient.exchangeCode(code, codeVerifier);
            JWTClaimsSet claims = idTokenValidator.validate(tokens.idToken(), expectedNonce);

            // One-time flow secrets are no longer needed; drop them.
            session.removeAttribute(SESSION_STATE);
            session.removeAttribute(SESSION_NONCE);
            session.removeAttribute(SESSION_CODE_VERIFIER);

            // Persist a minimal "logged-in" session, including the refresh token for silent renewal.
            session.setAttribute(SESSION_CLAIMS, toDisplayClaims(claims));
            session.setAttribute(SESSION_ACCESS_TOKEN, tokens.accessToken());
            session.setAttribute(SESSION_ID_TOKEN, tokens.idToken());
            session.setAttribute(SESSION_REFRESH_TOKEN, tokens.refreshToken());

            log.info("User {} logged in", claims.getSubject());
            return new RedirectView("/profile");
        } catch (Exception e) {
            model.addAttribute("error", "login_failed");
            model.addAttribute("errorDescription", e.getMessage());
            return "error";
        }
    }

    /**
     * Step 3 &mdash; the signed-in landing page. Shows the identity claims from the ID token and the
     * live results of calling the resource server's API with the access token.
     *
     * <p>If a call comes back {@code 401} (the access token expired), we transparently use the stored
     * refresh token to obtain a fresh access token and retry &mdash; no re-login. If the refresh itself
     * fails (the refresh token expired or was already rotated), we fall back to the full login flow.
     */
    @GetMapping("/profile")
    @SuppressWarnings("unchecked")
    public Object profile(HttpSession session, Model model) {
        Map<String, Object> claims = (Map<String, Object>) session.getAttribute(SESSION_CLAIMS);
        String accessToken = (String) session.getAttribute(SESSION_ACCESS_TOKEN);
        if (claims == null || accessToken == null) {
            // Not logged in -> start the flow.
            return new RedirectView("/login");
        }

        // Call the API; if the token has expired, silently refresh once and retry.
        ResourceServerClient.ApiResult me = resourceServerClient.get("/api/me", accessToken);
        boolean tokenRefreshed = false;
        if (me.status() == 401) {
            String refreshToken = (String) session.getAttribute(SESSION_REFRESH_TOKEN);
            if (refreshToken != null) {
                try {
                    TokenClient.TokenResponse renewed = tokenClient.refresh(refreshToken);
                    accessToken = renewed.accessToken();
                    session.setAttribute(SESSION_ACCESS_TOKEN, accessToken);
                    if (renewed.idToken() != null) {
                        session.setAttribute(SESSION_ID_TOKEN, renewed.idToken());
                    }
                    // The OP rotates refresh tokens, so replace the stored one with the new value.
                    if (renewed.refreshToken() != null) {
                        session.setAttribute(SESSION_REFRESH_TOKEN, renewed.refreshToken());
                    }
                    tokenRefreshed = true;
                    log.info("Access token expired; refreshed silently for {}", claims.get("sub"));
                    me = resourceServerClient.get("/api/me", accessToken); // retry with the new token
                } catch (TokenClient.TokenExchangeException e) {
                    // Refresh token is gone too -> the user must authenticate again.
                    log.info("Refresh failed ({}); forcing re-login", e.getMessage());
                    session.invalidate();
                    return new RedirectView("/login");
                }
            }
        }

        ResourceServerClient.ApiResult messages = resourceServerClient.get("/api/messages", accessToken);

        model.addAttribute("claims", claims);
        model.addAttribute("accessTokenPreview", preview(accessToken));
        model.addAttribute("idTokenPreview", preview((String) session.getAttribute(SESSION_ID_TOKEN)));
        model.addAttribute("refreshTokenPreview", preview((String) session.getAttribute(SESSION_REFRESH_TOKEN)));
        model.addAttribute("tokenRefreshed", tokenRefreshed);
        model.addAttribute("meStatus", me.status());
        model.addAttribute("meBody", me.body());
        model.addAttribute("messagesStatus", messages.status());
        model.addAttribute("messagesBody", messages.body());
        return "profile";
    }

    /** Clears the local session. (The OP session is separate; this is just RP logout.) */
    @GetMapping("/logout")
    public RedirectView logout(HttpSession session) {
        session.invalidate();
        return new RedirectView("/");
    }

    /** Selects the claims we want to display from the validated ID token. */
    private Map<String, Object> toDisplayClaims(JWTClaimsSet claims) {
        Map<String, Object> display = new LinkedHashMap<>();
        display.put("sub", claims.getSubject());
        display.put("iss", claims.getIssuer());
        display.put("aud", claims.getAudience());
        putIfPresent(display, "name", claims.getClaim("name"));
        putIfPresent(display, "preferred_username", claims.getClaim("preferred_username"));
        putIfPresent(display, "email", claims.getClaim("email"));
        putIfPresent(display, "email_verified", claims.getClaim("email_verified"));
        if (claims.getExpirationTime() != null) {
            display.put("exp", claims.getExpirationTime().toInstant().toString());
        }
        return display;
    }

    private void putIfPresent(Map<String, Object> map, String key, Object value) {
        if (value != null) {
            map.put(key, value);
        }
    }

    /** Shows only the first chunk of a token so the page hints at it without dumping the whole JWT. */
    private String preview(String token) {
        if (token == null) {
            return "";
        }
        return token.length() <= 48 ? token : token.substring(0, 48) + "...";
    }

    private String toQuery(Map<String, String> params) {
        StringBuilder sb = new StringBuilder();
        params.forEach((k, v) -> {
            if (sb.length() > 0) {
                sb.append('&');
            }
            sb.append(URLEncoder.encode(k, StandardCharsets.UTF_8))
              .append('=')
              .append(URLEncoder.encode(v, StandardCharsets.UTF_8));
        });
        return sb.toString();
    }
}
