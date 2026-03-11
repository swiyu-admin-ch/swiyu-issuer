package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.domain.openid.CachedNonce;
import ch.admin.bj.swiyu.issuer.domain.openid.CachedNonceRepository;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.NonceSecret;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.NonceSecretRepository;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.SelfContainedNonce;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.NonceResponseDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.*;

class NonceServiceTest {

    private ApplicationProperties applicationProperties;
    private CachedNonceRepository cachedNonceRepository;
    private NonceService nonceService;
    private NonceSecret nonceSecret;

    @BeforeEach
    void setUp() {
        
        applicationProperties = mock(ApplicationProperties.class);
        cachedNonceRepository = mock(CachedNonceRepository.class);
        var nonceSecretRepository = mock(NonceSecretRepository.class);
        nonceService = new NonceService(applicationProperties, cachedNonceRepository, nonceSecretRepository);

        nonceSecret = NonceSecret.builder().id(UUID.randomUUID()).build();
        when(nonceSecretRepository.findAll()).thenReturn(List.of(nonceSecret));
    }

    @Test
    void testCreateNonce() {
        NonceResponseDto dto = nonceService.createNonce();
        assertNotNull(dto.nonce());
    }

    @Test
    void testIsUsedNonce_withoutUsage() {
        var nonce = new SelfContainedNonce(nonceSecret);
        when(cachedNonceRepository.findById(nonce.getNonceId())).thenReturn(Optional.empty());
        assertFalse(nonceService.isUsedNonce(nonce));
    }

    @Test
    void testIsUsedNonce_withUsage() {
        var nonce = new SelfContainedNonce(nonceSecret);

        when(cachedNonceRepository.findById(nonce.getNonceId())).thenReturn(Optional.of(new CachedNonce(nonce.getNonceId(), nonce.getNonceInstant())));
        assertTrue(nonceService.isUsedNonce(nonce));
    }

    @Test
    void testRegisterNonce() {
        var nonce = new SelfContainedNonce(nonceSecret);
        nonceService.registerNonce(nonce);
        verify(cachedNonceRepository).save(any());
    }

    @Test
    void testInvalidateSelfContainedNonce() {
        var nonceStr = new SelfContainedNonce(nonceSecret);
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