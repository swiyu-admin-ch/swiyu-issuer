package ch.admin.bj.swiyu.issuer.service.statusregistry;

import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.common.exception.JsonException;
import ch.admin.bj.swiyu.issuer.domain.ecosystem.TokenApi;
import ch.admin.bj.swiyu.issuer.domain.ecosystem.TokenSet;
import ch.admin.bj.swiyu.issuer.domain.ecosystem.TokenSetRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.core.LockAssert;
import net.javacrumbs.shedlock.core.LockConfiguration;
import net.javacrumbs.shedlock.core.LockingTaskExecutor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

import static ch.admin.bj.swiyu.issuer.domain.ecosystem.EcosystemApiType.STATUS_REGISTRY;

/**
 * Service for managing OAuth token sets for the Status Registry API in the Swiyu ecosystem.
 * <p>
 * This service is responsible for securely obtaining, refreshing, and storing OAuth token sets
 * required to access the Status Registry. It supports both the client_credentials and refresh_token
 * grant types, and is designed for safe operation in horizontally scaled (clustered) environments
 * using distributed locking (ShedLock).
 * </p>
 *
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class StatusRegistryTokenService {
    private final SwiyuProperties swiyuProperties;
    private final TokenSetRepository tokenSetRepository;
    private final LockingTaskExecutor lockingTaskExecutor;

    private final LockConfiguration statusRegistryTokenApiLockConfiguration;
    private final TokenApi statusRegistryTokenApi;

    /**
     * Initializes the token set at application startup. Uses distributed lock to ensure only one instance runs this.
     */
    @PostConstruct
    void bootstrapTokenSetRefresh() {
        lockingTaskExecutor.executeWithLock(
                (Runnable) () -> {
                    log.info("Bootstrapping Status Registry OAuth token set with this instance (application startup).");
                    try {
                        requestNewTokenSet();
                    } catch (Exception e) {
                        log.error("Could not update Status Registry OAuth token set during bootstrap. Refresh token might be already used or misconfigured.", e);
                    }
                },
                statusRegistryTokenApiLockConfiguration);
    }

    /**
     * Returns the current access token for the Status Registry API.
     *
     * @return Encoded access token
     */
    @Transactional(readOnly = true)
    public String getAccessToken() {
        var dbData = tokenSetRepository.findById(STATUS_REGISTRY)
                .orElseThrow(() -> new IllegalStateException("Failed to lookup authorization token for accessing the " +
                        "status registry. There was no token provided under the key 'STATUS_REGISTRY'."));
        return dbData.getAccessToken();
    }

    /**
     * Forces a refresh of the token set and returns the new access token.
     *
     * @return New encoded access token
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
     * Requests a new token set from the provider using the given refresh token or client credentials.
     *
     * @param refreshToken Optional refresh token
     * @return Token provider response
     */
    private TokenApi.TokenResponse getTokenResponse(String refreshToken) {
        var prop = swiyuProperties.statusRegistry();
        if (prop.enableRefreshTokenFlow() && refreshToken != null) {
            log.info("Refreshing Status Registry OAuth access and refresh token with existing refresh token and secret grant_type: refresh_token");
            return statusRegistryTokenApi.getNewToken(
                    prop.customerKey(),
                    prop.customerSecret(),
                    refreshToken,
                    "refresh_token");
        }
        if (prop.enableRefreshTokenFlow()) {
            log.debug("Refresh token flow enabled but no refresh token provided. Falling back to client_credentials grant type.");
        } else {
            log.info("Refreshing Status Registry OAuth token set with grant_type: client_credentials (no refresh token used).");
        }
        return statusRegistryTokenApi.getNewToken(
                prop.customerKey(),
                prop.customerSecret(),
                "client_credentials");
    }

    /**
     * Refreshes and persists the OAuth token set for the Status Registry API.
     * <p>
     * This method must be called only when the distributed lock for the Status Registry token is held.
     * It attempts to refresh the token set using the refresh token from the database. If this fails,
     * or if no token exists in the database, it falls back to using the bootstrap refresh token from the configuration.
     * The new token set is then saved to the database.
     * </p>
     *
     * <b>Locking:</b> This method asserts that the ShedLock lock is held. Do not call this method outside a locked context.
     *
     * @return the newly obtained and persisted {@link TokenSet}
     * @throws IllegalStateException if called without the required lock
     */
    public TokenSet requestNewTokenSet() {
        LockAssert.assertLocked();

        var dbData = tokenSetRepository.findById(STATUS_REGISTRY);

        TokenApi.TokenResponse tokenResponse = dbData
                .flatMap(token -> Optional.ofNullable(this.tryRefreshWithDbToken(token)))
                .orElseGet(this::refreshWithBootstrapToken);

        // save new token set data to db
        TokenSet tokenSet = dbData.orElseGet(TokenSet::new);
        tokenSet.apply(STATUS_REGISTRY, tokenResponse);
        log.info("Status Registry OAuth token set updated successfully in DB.");
        return tokenSetRepository.save(tokenSet);
    }

    private TokenApi.TokenResponse tryRefreshWithDbToken(TokenSet dbTokenSet) {
        try {
            // if initialized: try it with the token in the DB

            var tokenResponse = getTokenResponse(dbTokenSet.getRefreshToken());
            log.info("Status Registry OAuth refresh token set based on refresh token in DB (refreshToken: {}).", dbTokenSet.getRefreshToken());
            return tokenResponse;

        } catch (Exception e) {
            log.error("Failed to refresh Status Registry OAuth token set with DB token. Falling back to bootstrap token.", e);
            return null;
        }

    }

    private TokenApi.TokenResponse refreshWithBootstrapToken() {
        // if initialized, but it did not work with the DB token: try with the bootstrap token
        // this is the case after the service did not run the auth flow for more than 7 days
        log.warn("Status Registry OAuth refresh token set based on bootstrap configuration (no token in DB or DB token invalid). Using bootstrap refresh token.");
        return getTokenResponse(swiyuProperties.statusRegistry().bootstrapRefreshToken());
    }
}