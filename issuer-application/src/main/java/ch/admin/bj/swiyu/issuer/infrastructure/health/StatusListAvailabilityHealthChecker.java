package ch.admin.bj.swiyu.issuer.infrastructure.health;

import ch.admin.bj.swiyu.core.status.registry.client.api.StatusB2BApi;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.common.logging.ResponseBodyLogFormatter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.health.contributor.Health;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClientException;
import org.springframework.web.reactive.function.client.WebClientResponseException;

@Component
@RequiredArgsConstructor
@Slf4j
@ConditionalRegistryHealthChecksEnabled
public class StatusListAvailabilityHealthChecker extends CachedHealthChecker {

    private final StatusB2BApi statusBusinessApi;
    private final SwiyuProperties swiyuProperties;

    @Override
    protected void performCheck(Health.Builder builder) throws Exception {
        builder.withDetail("partnerId", swiyuProperties.businessPartnerId());

        try {
            statusBusinessApi.getAllStatusListEntries(swiyuProperties.businessPartnerId(), 0, 1, null).block();
            builder.up();
            return;
        } catch (WebClientResponseException e) {
            log.warn("Health check for status list of partner {} failed: {}", this.swiyuProperties.businessPartnerId(),
                    ResponseBodyLogFormatter.describe(e));
        } catch (WebClientException e) {
            log.warn("Health check for status list of partner {} failed: {}", this.swiyuProperties.businessPartnerId(), e.getMessage());
        }
        builder.down();
    }
}