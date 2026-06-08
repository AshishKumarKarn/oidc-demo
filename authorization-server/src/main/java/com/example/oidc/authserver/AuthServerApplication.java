package com.example.oidc.authserver;

import com.example.oidc.authserver.config.AuthServerProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/**
 * Entry point for the OpenID Provider (OP) / Authorization Server.
 *
 * <p>This application implements the OpenID Connect 1.0 "Authorization Code Flow with PKCE"
 * from scratch. It exposes the standard OIDC endpoints:
 * <ul>
 *   <li>{@code GET  /.well-known/openid-configuration} &ndash; discovery document</li>
 *   <li>{@code GET  /.well-known/jwks.json} &ndash; public signing keys (JWK Set)</li>
 *   <li>{@code GET  /authorize} &ndash; authorization endpoint (renders the login page)</li>
 *   <li>{@code POST /login} &ndash; authenticates the user and issues an authorization code</li>
 *   <li>{@code POST /token} &ndash; token endpoint (exchanges code for id_token + access_token)</li>
 *   <li>{@code GET  /userinfo} &ndash; UserInfo endpoint (claims for a valid access token)</li>
 * </ul>
 */
@SpringBootApplication
@EnableConfigurationProperties(AuthServerProperties.class)
public class AuthServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthServerApplication.class, args);
    }
}
