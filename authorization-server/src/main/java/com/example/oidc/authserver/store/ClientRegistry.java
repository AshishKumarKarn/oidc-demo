package com.example.oidc.authserver.store;

import com.example.oidc.authserver.model.OidcClient;
import org.springframework.stereotype.Repository;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory registry of trusted clients.
 *
 * <p>A production OP would persist this in a database and expose a Dynamic Client Registration API.
 * Here we seed a single demo client matching the {@code client-app} project.
 */
@Repository
public class ClientRegistry {

    private final Map<String, OidcClient> clients = new ConcurrentHashMap<>();

    public ClientRegistry() {
        // This must line up with the client-app's application.yml.
        OidcClient demoClient = new OidcClient(
                "demo-client",
                "demo-secret",
                Set.of("http://localhost:8080/callback"),
                Set.of("openid", "profile", "email", "api.read"));
        clients.put(demoClient.clientId(), demoClient);
    }

    public Optional<OidcClient> findByClientId(String clientId) {
        return Optional.ofNullable(clients.get(clientId));
    }
}
