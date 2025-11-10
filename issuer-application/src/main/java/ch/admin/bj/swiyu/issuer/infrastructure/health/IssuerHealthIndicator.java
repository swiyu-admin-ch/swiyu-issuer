package ch.admin.bj.swiyu.issuer.infrastructure.health;


import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Aggregates the cached results of individual health checkers into a single indicator.
 * <p>Propagates DOWN if any underlying checker is not UP and exposes each checkers details.</p>
 */
@Component
public class IssuerHealthIndicator implements HealthIndicator {

    /** Cached status registry endpoint checks. */
    private final StatusRegistryIssuerHealthChecker statusRegistryIssuer;
    /** Cached DID / identifier resolution checks. */
    private final IdentifierRegistryHealthChecker identifierRegistry;

    public IssuerHealthIndicator(StatusRegistryIssuerHealthChecker statusRegistryIssuer,
                                 IdentifierRegistryHealthChecker identifierRegistry) {
        this.statusRegistryIssuer = statusRegistryIssuer;
        this.identifierRegistry = identifierRegistry;
    }

    /**
     * Builds an aggregate {@link Health} from the latest cached results of the injected checkers.
     * Adds each checker\n's details under its name; overall status becomes first non-UP encountered.
     */
    @Override
    public Health health() {
        Health.Builder builder = Health.up();

        Map<String, Health> checks = Map.of(
                "statusRegistryIssuer", statusRegistryIssuer.getHealthResult(),
                "identifierRegistry", identifierRegistry.getHealthResult()
        );

        checks.forEach((name, health) -> {
            builder.withDetail(name, health.getDetails());
            if (!health.getStatus().equals(Health.up().build().getStatus())) {
                builder.status(health.getStatus());
            }
        });

        return builder.build();
    }
}
