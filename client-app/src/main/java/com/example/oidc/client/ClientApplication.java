package com.example.oidc.client;

import com.example.oidc.client.config.ClientProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/**
 * Entry point for the relying party / service provider (the web app users actually log in to).
 *
 * <p>It implements the OIDC Authorization Code Flow with PKCE end-to-end, by hand:
 * <ol>
 *   <li>{@code GET /login} &ndash; generate {@code state}, {@code nonce} and a PKCE verifier/challenge,
 *       stash them in the session, and redirect the browser to the OP's authorization endpoint.</li>
 *   <li>{@code GET /callback} &ndash; verify {@code state}, exchange the {@code code} for tokens at the
 *       OP's token endpoint (sending the PKCE verifier), validate the {@code id_token}, and create a
 *       local session.</li>
 *   <li>{@code GET /profile} &ndash; show the identity claims and call the resource server's API using
 *       the access token.</li>
 * </ol>
 */
@SpringBootApplication
@EnableConfigurationProperties(ClientProperties.class)
public class ClientApplication {

    public static void main(String[] args) {
        SpringApplication.run(ClientApplication.class, args);
    }
}
