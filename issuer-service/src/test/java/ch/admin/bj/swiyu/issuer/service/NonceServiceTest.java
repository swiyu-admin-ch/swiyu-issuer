package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.dto.oid4vci.NonceResponseDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.domain.openid.CachedNonce;
import ch.admin.bj.swiyu.issuer.domain.openid.CachedNonceRepository;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.SelfContainedNonce;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class NonceServiceTest {

    private ApplicationProperties applicationProperties;
    private CachedNonceRepository cachedNonceRepository;
    private NonceService nonceService;

    @BeforeEach
    void setUp() {
        applicationProperties = mock(ApplicationProperties.class);
        cachedNonceRepository = mock(CachedNonceRepository.class);
        nonceService = new NonceService(applicationProperties, cachedNonceRepository);
    }

    @Test
    void testCreateNonce() {
        NonceResponseDto dto = nonceService.createNonce();
        assertNotNull(dto.nonce());
    }

    @Test
    void testIsUsedNonce_withoutUsage() {
        var nonce = new SelfContainedNonce();
        when(cachedNonceRepository.findById(nonce.getNonceId())).thenReturn(Optional.empty());
        assertFalse(nonceService.isUsedNonce(nonce));
    }

    @Test
    void testIsUsedNonce_withUsage() {
        var nonce = new SelfContainedNonce();

        when(cachedNonceRepository.findById(nonce.getNonceId())).thenReturn(Optional.of(new CachedNonce(nonce.getNonceId(), nonce.getNonceInstant())));
        assertTrue(nonceService.isUsedNonce(nonce));
    }

    @Test
    void testRegisterNonce() {
        var nonce = new SelfContainedNonce();
        nonceService.registerNonce(nonce);
        verify(cachedNonceRepository).save(any());
    }

    @Test
    void testInvalidateSelfContainedNonce() {
        var nonceStr = new SelfContainedNonce().getNonce();
        nonceService.invalidateSelfContainedNonce(List.of(nonceStr));
        verify(cachedNonceRepository).saveAll(anyList());
    }

    @Test
    void testCleanNonceCache() {
        when(applicationProperties.getNonceLifetimeSeconds()).thenReturn(60);
        nonceService.cleanNonceCache();
        verify(cachedNonceRepository).deleteAllOlderThan(any(Instant.class));
    }
}