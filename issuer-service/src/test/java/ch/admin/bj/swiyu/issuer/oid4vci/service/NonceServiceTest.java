package ch.admin.bj.swiyu.issuer.oid4vci.service;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.domain.openid.CachedNonceRepository;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.SelfContainedNonce;
import ch.admin.bj.swiyu.issuer.service.NonceService;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.springframework.transaction.annotation.Transactional;


import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;


class NonceServiceTest {

    @Mock
    private ApplicationProperties applicationProperties;

    @Mock
    private CachedNonceRepository nonceRepository;


    @Test
    void testCreateNonce() {
        var service = new NonceService(applicationProperties, nonceRepository);
        var nonceDto = service.createNonce();
        var nonceString = nonceDto.nonce();
        var nonce = new SelfContainedNonce(nonceString);
        assertTrue(nonce.isValid((1)));
        assertTrue(nonceString.startsWith(nonce.getNonceId().toString()));
        assertTrue(nonceString.endsWith(nonce.getNonceInstant().toString()));
    }
}
