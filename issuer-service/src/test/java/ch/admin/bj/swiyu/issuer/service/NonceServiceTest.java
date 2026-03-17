package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.domain.openid.CachedNonce;
import ch.admin.bj.swiyu.issuer.domain.openid.CachedNonceRepository;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.IssuerSecret;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.IssuerSecretRepository;
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
    private IssuerSecret nonceSecret;

    @BeforeEach
    void setUp() {
        
        applicationProperties = mock(ApplicationProperties.class);
        cachedNonceRepository = mock(CachedNonceRepository.class);
        var nonceSecretRepository = mock(IssuerSecretRepository.class);
        nonceService = new NonceService(applicationProperties, cachedNonceRepository, nonceSecretRepository);

        nonceSecret = IssuerSecret.builder().id(UUID.randomUUID()).build();
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

    @Test
    void isValid_shouldReturnTrue_whenNonceIsValid() {
        var nonce = new SelfContainedNonce(nonceSecret);
        assertTrue(nonce.isValid(60, nonceSecret));
    }

    @Test
    void isValid_shouldReturnFalse_whenNonceIsExpired() {
        var nonce = new SelfContainedNonce(nonceSecret);

        var expiredInstant = Instant.now().minusSeconds(120);
        var preNonce = nonce.getNonceId() + "::" + expiredInstant;
        var signature = SelfContainedNonce.createSignature(preNonce, nonceSecret);
        var expiredNonce = new SelfContainedNonce(preNonce + "::" + signature);

        assertFalse(expiredNonce.isValid(60, nonceSecret));
    }

    @Test
    void isValid_shouldReturnFalse_whenSignatureIsInvalid() {
        var nonce = new SelfContainedNonce(nonceSecret);

        var invalidNonce = new SelfContainedNonce(
                nonce.getPreNonce() + "::invalid-signature"
        );

        assertFalse(invalidNonce.isValid(60, nonceSecret));
    }
}