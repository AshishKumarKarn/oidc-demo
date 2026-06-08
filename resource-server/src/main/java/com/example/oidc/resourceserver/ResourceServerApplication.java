package com.example.oidc.resourceserver;

import com.example.oidc.resourceserver.config.ResourceServerProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/**
 * Entry point for the protected API (OAuth 2.0 Resource Server).
 *
 * <p>This service trusts no caller by default. Every request to {@code /api/**} must carry a valid
 * {@code Authorization: Bearer <access_token>} header. The token is a JWT signed by the OP; this
 * server validates it statelessly by:
 * <ul>
 *   <li>fetching the OP's JWK Set and selecting the key matching the token's {@code kid},</li>
 *   <li>verifying the RS256 signature,</li>
 *   <li>checking {@code iss}, {@code aud} and {@code exp}.</li>
 * </ul>
 * Endpoint-level authorization is then enforced from the token's {@code scope} claim.
 */
@SpringBootApplication
@EnableConfigurationProperties(ResourceServerProperties.class)
public class ResourceServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(ResourceServerApplication.class, args);
    }
}
