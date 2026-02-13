package ch.admin.bj.swiyu.issuer.infrastructure.health;

import ch.admin.bj.swiyu.core.status.registry.client.api.StatusBusinessApiApi;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.health.Health;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClientException;

@Component
public class StatusListAvailabilityHealthChecker extends CachedHealthChecker {

    private final StatusBusinessApiApi statusBusinessApi;
    private final SwiyuProperties swiyuProperties;

    @Autowired
    public StatusListAvailabilityHealthChecker(StatusBusinessApiApi statusBusinessApi, SwiyuProperties swiyuProperties) {
        this.statusBusinessApi = statusBusinessApi;
        this.swiyuProperties = swiyuProperties;
    }

    @Override
    protected void performCheck(Health.Builder builder) throws Exception {
        builder.withDetail("partnerId", swiyuProperties.businessPartnerId());
        try {
            statusBusinessApi.getAllStatusListEntries(swiyuProperties.businessPartnerId(), 0, 1, null).block();
            builder.up();
            return;
        } catch (WebClientException ignoredException) {
        }
        builder.down();
    }
}