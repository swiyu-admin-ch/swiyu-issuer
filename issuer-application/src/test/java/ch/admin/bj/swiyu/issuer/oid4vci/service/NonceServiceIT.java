package ch.admin.bj.swiyu.issuer.oid4vci.service;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.SelfContainedNonce;
import ch.admin.bj.swiyu.issuer.service.NonceService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;


@SpringBootTest
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
class NonceServiceIT {
    @Autowired
    private ApplicationProperties applicationProperties;

    @Autowired
    private NonceService service;

    @Test
    void testCachedNonce() {
        var lifetime = applicationProperties.getNonceLifetimeSeconds();
        var nonceDto = service.createNonce();
        var nonce = new SelfContainedNonce(nonceDto.nonce(), lifetime);
        assertFalse(service.isUsedNonce(nonce));
        service.registerNonce(nonce);
        assertTrue(service.isUsedNonce(nonce));
    }
}