/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.service.statusregistry;

import ch.admin.bj.swiyu.issuer.management.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.management.common.exception.JsonException;
import ch.admin.bj.swiyu.issuer.management.domain.ecosystem.EcosystemApiType;
import ch.admin.bj.swiyu.issuer.management.domain.ecosystem.TokenApi;
import ch.admin.bj.swiyu.issuer.management.domain.ecosystem.TokenSet;
import ch.admin.bj.swiyu.issuer.management.domain.ecosystem.TokenSetRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.core.LockAssert;
import net.javacrumbs.shedlock.core.LockConfiguration;
import net.javacrumbs.shedlock.core.LockingTaskExecutor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/**
 * A service to interact with the status registry token provider from the swiyu
 * ecosystem.
 * Utilizes database and lock functionality to enable horizontal scaling of the
 * application.
 */
@Slf4j
@RequiredArgsConstructor
@Service
public class StatusRegistryTokenDomainService {
    private final SwiyuProperties swiyuProperties;
    private final TokenSetRepository tokenSetRepository;
    private final LockingTaskExecutor lockingTaskExecutor;

    private final LockConfiguration statusRegistryTokenApiLockConfiguration;
    private final TokenApi statusRegistryTokenApi;

    private final EcosystemApiType thisApi = EcosystemApiType.STATUS_REGISTRY;

    /**
     * Initial token set refresh flow.
     * Starts once after all other application startup is done.
     */
    @Scheduled(initialDelay = 0)
    void bootstrapTokenSetRefresh() {
        lockingTaskExecutor.executeWithLock(
                (Runnable) () -> {
                    log.info("Bootstrapping token set with this instance.");
                    try {
                        requestNewTokenSet();
                    } catch (Exception e) {
                        log.error("Could not update token set. Refresh token might be already used.", e);
                    }
                },
                statusRegistryTokenApiLockConfiguration);
    }

    /**
     * Regular refresh of token set to prevent tokens going stale
     */
    @Scheduled(initialDelayString = "${swiyu.status-registry.token-refresh-interval}", fixedDelayString = "${swiyu.status-registry.token-refresh-interval}")
    void refreshTokenSets() {
        lockingTaskExecutor.executeWithLock(
                (Runnable) () -> {
                    log.info("Refresh token set with this instance.");
                    try {
                        var dbData = tokenSetRepository.findById(thisApi);
                        if (dbData.isEmpty() || Instant.now().plusSeconds(1).isAfter(
                                dbData.get().getLastRefresh()
                                        .plus(swiyuProperties.statusRegistry().tokenRefreshInterval()))) {
                            requestNewTokenSet();
                        } else {
                            log.debug("No need to update token set.");
                        }
                    } catch (Exception e) {
                        log.error(
                                "Could not update token set. Are credentials (might be the refresh token) out of sync?",
                                e);
                    }

                },
                statusRegistryTokenApiLockConfiguration);
    }

    /**
     * Get the current access Token
     *
     * @return Encoded access token for current use
     */
    @Transactional(readOnly = true)
    public String getAccessToken() {
        var dbData = tokenSetRepository.findById(thisApi)
                .orElseThrow(() -> new IllegalArgumentException("TODO"));
        return dbData.getAccessToken();
    }

    /**
     * Refreshes the token set without checking if it needs a refresh
     *
     * @return Encoded access token for current use
     */
    @Transactional
    public String forceRefreshAccessToken() {
        try {
            return lockingTaskExecutor.executeWithLock(
                    () -> requestNewTokenSet().getAccessToken(),
                    statusRegistryTokenApiLockConfiguration).getResult();
        } catch (Throwable e) {
            throw new JsonException("forceRefreshAccessToken failed", e);
        }
    }

    /**
     * Request a new token set at the token provider.
     *
     * @param refreshToken optional refresh token to use. If not provided
     *                     client_credentials flow will be used.
     * @return The providers response with new tokens
     */
    private TokenApi.TokenResponse getTokenResponse(String refreshToken) {
        var prop = swiyuProperties.statusRegistry();
        TokenApi.TokenResponse token_result;

        if (prop.enableRefreshTokenFlow() && refreshToken != null) {
            log.debug("Refreshing token set with grant_type: refresh_token");
            token_result = statusRegistryTokenApi.getNewToken(
                    prop.customerKey(),
                    prop.customerSecret(),
                    refreshToken,
                    "refresh_token");

        } else {
            log.debug("Refreshing token set with grant_type: client_credentials");
            token_result = statusRegistryTokenApi.getNewToken(
                    prop.customerKey(),
                    prop.customerSecret(),
                    "client_credentials");
        }
        return token_result;
    }

    /**
     * Request a new token set at the token provider, tries different configuration
     * options.
     *
     * @return TokenSet the new, and therefore current, token set to use.
     */
    private TokenSet requestNewTokenSet() {
        // this method should only be called from locked context
        LockAssert.assertLocked();

        // check old config
        var dbData = tokenSetRepository.findById(thisApi);
        TokenApi.TokenResponse tokenResponse;
        if (dbData.isEmpty()) {
            // if not initialized: try it with the bootstrap token
            tokenResponse = getTokenResponse(swiyuProperties.statusRegistry().bootstrapRefreshToken());
            log.debug("Refreshed token set based on bootstrap configuration.");
        } else {
            try {
                // if initialized: try it with the token in the DB
                tokenResponse = getTokenResponse(dbData.get().getRefreshToken());
                log.debug("Refreshed token set based on refresh token in db.");
            } catch (Exception e) {
                // if initialized, but it did not work with the DB token: try with the bootstrap
                // token
                // this is the case after the service did not run the auth flow for more than 7
                // days
                tokenResponse = getTokenResponse(swiyuProperties.statusRegistry().bootstrapRefreshToken());
                log.debug("Refreshed token set based on bootstrap token as token in db was invalid.");
            }
        }
        // save new token set data to db
        TokenSet saveTo = dbData.orElseGet(TokenSet::new);
        saveTo.apply(thisApi, tokenResponse);
        log.debug("Token set update successfully.");
        return tokenSetRepository.save(saveTo);
    }
}
