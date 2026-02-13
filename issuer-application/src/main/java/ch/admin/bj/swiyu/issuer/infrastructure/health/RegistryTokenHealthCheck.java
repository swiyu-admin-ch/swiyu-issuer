package ch.admin.bj.swiyu.issuer.infrastructure.health;

import ch.admin.bj.swiyu.issuer.domain.ecosystem.EcosystemApiType;
import ch.admin.bj.swiyu.issuer.domain.ecosystem.TokenSetRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.health.Health;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;

@Component
public class RegistryTokenHealthCheck extends CachedHealthChecker {

    private final TokenSetRepository tokenSetRepository;
    private final Duration tokenRefreshInterval;

    @Autowired
    public RegistryTokenHealthCheck(TokenSetRepository tokenSetRepository, @Value( "${swiyu.status-registry.token-refresh-interval}" ) Duration tokenRefreshInterval) {
        this.tokenSetRepository = tokenSetRepository;
        this.tokenRefreshInterval = tokenRefreshInterval;
    }

    @Override
    protected void performCheck(Health.Builder builder) throws Exception {
        var dbData = tokenSetRepository.findById(EcosystemApiType.STATUS_REGISTRY);
        if (dbData.isEmpty()) {
            builder.down();
            return;
        }

        var lastRefresh = dbData.get().getLastRefresh();
        builder.withDetail("lastRefresh", lastRefresh);
        if (lastRefresh.isAfter(Instant.now().minus(tokenRefreshInterval))) {
            builder.up();
        } else {
            builder.down();
        }
    }
}
