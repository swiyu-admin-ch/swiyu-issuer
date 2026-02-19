package ch.admin.bj.swiyu.issuer.infrastructure.health;

import ch.admin.bj.swiyu.core.status.registry.client.api.StatusBusinessApiApi;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.actuate.health.Health;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClientException;

@Component
@RequiredArgsConstructor
@Slf4j
public class StatusListAvailabilityHealthChecker extends CachedHealthChecker {

    private final StatusBusinessApiApi statusBusinessApi;
    private final SwiyuProperties swiyuProperties;

    @Override
    protected void performCheck(Health.Builder builder) throws Exception {
        builder.withDetail("partnerId", swiyuProperties.businessPartnerId());
        try {
            statusBusinessApi.getAllStatusListEntries(swiyuProperties.businessPartnerId(), 0, 1, null).block();
            builder.up();
            return;
        } catch (WebClientException e) {
            log.debug("Health check for status list of partner {} failed: {}", this.swiyuProperties.businessPartnerId(), e.getMessage());
        }
        builder.down();
    }
}