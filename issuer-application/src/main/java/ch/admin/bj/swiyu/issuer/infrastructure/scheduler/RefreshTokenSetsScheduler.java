package ch.admin.bj.swiyu.issuer.infrastructure.scheduler;

import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.domain.ecosystem.TokenSetRepository;
import ch.admin.bj.swiyu.issuer.service.statusregistry.StatusRegistryTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.core.LockConfiguration;
import net.javacrumbs.shedlock.core.LockingTaskExecutor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;

import static ch.admin.bj.swiyu.issuer.domain.ecosystem.EcosystemApiType.STATUS_REGISTRY;

/**
 * Scheduler responsible for regularly refreshing the token set for the Status Registry API.
 * <p>
 * This scheduler ensures that the token set used for communication with the Status Registry
 * does not become stale by periodically checking the token's expiration and requesting a new
 * token set if necessary. The refresh interval is configured via the application properties
 * (swiyu.status-registry.token-refresh-interval).
 * <p>
 * The refresh operation is protected by a distributed lock (ShedLock) to prevent concurrent
 * refreshes in a clustered environment. If the token set is missing or about to expire, a new
 * token set is requested from the StatusRegistryTokenService. Any errors during the
 * refresh process are logged for troubleshooting.
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class RefreshTokenSetsScheduler {

    private final SwiyuProperties swiyuProperties;
    private final TokenSetRepository tokenSetRepository;
    private final LockingTaskExecutor lockingTaskExecutor;

    private final LockConfiguration statusRegistryTokenApiLockConfiguration;
    private final StatusRegistryTokenService statusRegistryTokenService;

    /**
     * Regular refresh of token set to prevent tokens going stale
     */
    @Scheduled(initialDelayString = "${swiyu.status-registry.token-refresh-interval}", fixedDelayString = "${swiyu.status-registry.token-refresh-interval}")
    void refreshTokenSets() {
        lockingTaskExecutor.executeWithLock(
                (Runnable) () -> {
                    log.debug("Refresh token set with this instance.");
                    try {
                        var dbData = tokenSetRepository.findById(STATUS_REGISTRY);
                        if (dbData.isEmpty() || Instant.now().plusSeconds(1).isAfter(
                                dbData.get().getLastRefresh()
                                        .plus(swiyuProperties.statusRegistry().tokenRefreshInterval()))) {
                            statusRegistryTokenService.requestNewTokenSet();
                        } else {
                            log.debug("No need to update token set.");
                        }
                    } catch (Exception e) {
                        log.error(
                                "Could not update token set. Are credentials or refresh token out of sync or incorrect?",
                                e);
                    }

                },
                statusRegistryTokenApiLockConfiguration);
    }


}
