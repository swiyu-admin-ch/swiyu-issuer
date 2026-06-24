package ch.admin.bj.swiyu.issuer.oid4vci.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cache.CacheManager;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.testcontainers.junit.jupiter.Testcontainers;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.CacheConfig;
import ch.admin.bj.swiyu.issuer.domain.openid.CachedNonceRepository;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.SelfContainedNonce;
import ch.admin.bj.swiyu.issuer.service.NonceService;


@SpringBootTest
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
class NonceServiceIT {
    @Autowired
    private ApplicationProperties applicationProperties;

    @Autowired
    private NonceService service;

    @Autowired
    private CachedNonceRepository cachedNonceRepository;

    @Autowired
    private CacheManager cacheManager;

    /**
     * Prevents background {@code @Scheduled} jobs from running while this test
     * controls nonce cleanup explicitly through {@link NonceService#cleanNonceCache()}.
     */
    @MockitoBean
    private TaskScheduler taskScheduler;

    /**
     * The PostgreSQL Testcontainer is shared across all integration tests, so leftover
     * {@code cached_nonce} rows from earlier tests would otherwise leak in here and make
     * the assertions on {@code isUsedNonce} non-deterministic. The {@code IssuerSecret}
     * cache is also reset so that a stale secret from a previous test context does not
     * make the nonce signature verification flaky.
     */
    @BeforeEach
    void cleanState() {
        cachedNonceRepository.deleteAll();
        var issuerSecretCache = cacheManager.getCache(CacheConfig.ISSUER_SECRET_CACHE);
        if (issuerSecretCache != null) {
            issuerSecretCache.clear();
        }
    }

    @Test
    void testCachedNonce() {
        var lifetime = applicationProperties.getNonceLifetimeSeconds();
        var nonceDto = service.createNonce();
        var nonce = new SelfContainedNonce(nonceDto.nonce());
        var secret = service.getNonceSecret();
        assertTrue(nonce.isValid(lifetime, secret));
        assertFalse(service.isUsedNonce(nonce));
        service.registerNonce(nonce);
        assertTrue(service.isUsedNonce(nonce));

        var expiredPreNonce = UUID.randomUUID() + "::" + Instant.now().minus(lifetime + 5, ChronoUnit.SECONDS);
        var expiredNonce = new SelfContainedNonce(expiredPreNonce + "::" + SelfContainedNonce.createSignature(expiredPreNonce, secret));
        assertFalse(expiredNonce.isValid(lifetime, secret));
        assertFalse(service.isUsedNonce(expiredNonce));
        service.registerNonce(expiredNonce);
        assertTrue(service.isUsedNonce(expiredNonce));

        // After clearing the cache the expired nonce should be removed, as it is not valid in any check
        service.cleanNonceCache();
        assertTrue(service.isUsedNonce(nonce));
        assertFalse(service.isUsedNonce(expiredNonce));
    }
}
