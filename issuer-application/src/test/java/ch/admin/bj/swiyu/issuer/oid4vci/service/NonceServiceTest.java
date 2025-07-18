package ch.admin.bj.swiyu.issuer.oid4vci.service;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.SelfContainedNonce;
import ch.admin.bj.swiyu.issuer.service.NonceService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;


@SpringBootTest
@Testcontainers
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
class NonceServiceTest {
    @Autowired
    private ApplicationProperties applicationProperties;

    @Autowired
    private NonceService service;

    @Test
    void testCachedNonce() {
        var lifetime = applicationProperties.getNonceLifetimeSeconds();
        var nonceDto = service.createNonce();
        var nonce = new SelfContainedNonce(nonceDto.nonce());
        assertTrue(nonce.isValid((lifetime)));
        assertFalse(service.isUsedNonce(nonce));
        service.registerNonce(nonce);
        assertTrue(service.isUsedNonce(nonce));

        var expiredNonce = new SelfContainedNonce(UUID.randomUUID() + "::" + Instant.now().minus(lifetime + 2, ChronoUnit.SECONDS));
        assertFalse(expiredNonce.isValid(lifetime));
        assertFalse(service.isUsedNonce(expiredNonce));
        service.registerNonce(expiredNonce);
        assertTrue(service.isUsedNonce(expiredNonce));

        // After clearing the cache the expired nonce should be removed, as it is not valid in any check
        service.cleanNonceCache();
        assertTrue(service.isUsedNonce(nonce));
        assertFalse(service.isUsedNonce(expiredNonce));
    }
}