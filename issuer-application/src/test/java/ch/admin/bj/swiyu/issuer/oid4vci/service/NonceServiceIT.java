package ch.admin.bj.swiyu.issuer.oid4vci.service;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.SelfContainedNonce;
import ch.admin.bj.swiyu.issuer.service.NonceService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.orm.jpa.JpaSystemException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
class NonceServiceIT {
    @Autowired
    private ApplicationProperties applicationProperties;

    @Autowired
    private NonceService service;

    private SelfContainedNonce nonce;

    private SelfContainedNonce expiredNonce;

    @BeforeEach
    void setUp() {
        var lifetime = applicationProperties.getNonceLifetimeSeconds();
        var nonceDto = service.createNonce();
        nonce = new SelfContainedNonce(nonceDto.nonce());
        assertTrue(nonce.isValid((lifetime)));
        assertFalse(service.isUsedNonce(nonce));
        service.registerNonce(nonce);
        assertTrue(service.isUsedNonce(nonce));

        expiredNonce = new SelfContainedNonce(UUID.randomUUID() + "::" + Instant.now().minus(lifetime + 5, ChronoUnit.SECONDS));
        assertFalse(expiredNonce.isValid(lifetime));
        assertFalse(service.isUsedNonce(expiredNonce));
        service.registerNonce(expiredNonce);
        assertTrue(service.isUsedNonce(expiredNonce));
    }

    @Test
    void testCachedNonce() {
        // After clearing the cache the expired nonce should be removed, as it is not valid in any check
        service.cleanNonceCache();

        assertTrue(service.isUsedNonce(nonce));
        assertFalse(service.isUsedNonce(expiredNonce));
    }

    @Test
    @Transactional(readOnly = true)
    void testCleanNonceCacheWhenTransactionalIsReadOnlyThrowsUncheckedJpaSystemException() {

        // Dropping cache should not really be working at all in a read-only transactional context
        assertTrue(
                assertThrowsExactly(JpaSystemException.class, () -> service.cleanNonceCache())
                        .getMessage().contains("cannot execute DELETE in a read-only transaction"));
    }
}