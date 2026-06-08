package com.example.oidc.resourceserver.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * A public, unauthenticated endpoint used for health checks and to contrast with the protected
 * {@code /api/**} routes. It is reachable without any token because the bearer filter is only wired
 * to {@code /api/*}.
 */
@RestController
public class PublicController {

    @GetMapping("/")
    public Map<String, Object> home() {
        return Map.of(
                "service", "resource-server",
                "status", "up",
                "hint", "Call /api/me or /api/messages with a Bearer access token");
    }
}
