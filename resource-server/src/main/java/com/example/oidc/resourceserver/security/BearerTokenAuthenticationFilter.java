package com.example.oidc.resourceserver.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

/**
 * Servlet filter that enforces a valid Bearer access token on protected requests.
 *
 * <p>For every request it:
 * <ol>
 *   <li>extracts the token from the {@code Authorization: Bearer ...} header (401 if absent),</li>
 *   <li>validates it via {@link AccessTokenValidator} (401 if signature/claims fail),</li>
 *   <li>builds an {@link AuthenticatedToken} and stashes it on the request for controllers.</li>
 * </ol>
 *
 * <p>It is wired to {@code /api/*} only (see {@code FilterConfig}); public endpoints like the home
 * page are left unauthenticated.
 *
 * <p>Not a {@code @Component}: it is registered for the {@code /api/*} path only by
 * {@link com.example.oidc.resourceserver.config.FilterConfig}, so other paths stay public.
 */
public class BearerTokenAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(BearerTokenAuthenticationFilter.class);

    private final AccessTokenValidator validator;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public BearerTokenAuthenticationFilter(AccessTokenValidator validator) {
        this.validator = validator;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.startsWith("Bearer ")) {
            writeUnauthorized(response, "missing_token", "A Bearer access token is required");
            return;
        }

        String token = header.substring("Bearer ".length()).trim();
        try {
            JWTClaimsSet claims = validator.validate(token);
            AuthenticatedToken authenticated = AuthenticatedToken.fromClaims(claims);
            request.setAttribute(AuthenticatedToken.REQUEST_ATTRIBUTE, authenticated);
            log.debug("Authenticated request to {} for sub={} scopes={}",
                    request.getRequestURI(), authenticated.getSubject(), authenticated.getScopes());
            filterChain.doFilter(request, response);
        } catch (AccessTokenValidator.TokenValidationException e) {
            writeUnauthorized(response, "invalid_token", e.getMessage());
        } catch (Exception e) {
            writeUnauthorized(response, "invalid_token", "Token could not be processed");
        }
    }

    /** Emits an RFC 6750-style 401 with a JSON body and a {@code WWW-Authenticate} header. */
    private void writeUnauthorized(HttpServletResponse response, String error, String description)
            throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE,
                "Bearer error=\"" + error + "\", error_description=\"" + description + "\"");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getOutputStream(),
                Map.of("error", error, "error_description", description));
    }
}
