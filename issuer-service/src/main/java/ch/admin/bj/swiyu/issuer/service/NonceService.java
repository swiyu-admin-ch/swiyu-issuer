package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.CacheConfig;
import ch.admin.bj.swiyu.issuer.common.exception.InvalidNonceException;
import ch.admin.bj.swiyu.issuer.domain.openid.CachedNonce;
import ch.admin.bj.swiyu.issuer.domain.openid.CachedNonceRepository;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.SelfContainedNonce;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.IssuerSecret;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.IssuerSecretRepository;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.NonceResponseDto;
import lombok.AllArgsConstructor;

import org.springframework.cache.annotation.Cacheable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

@Service
@AllArgsConstructor
public class NonceService {
    private final ApplicationProperties applicationProperties;
    private final CachedNonceRepository cachedNonceRepository;
    private final IssuerSecretRepository issuerSecretRepository;

    public NonceResponseDto createNonce() {
        return new NonceResponseDto(new SelfContainedNonce(getNonceSecret()).getNonce());
    }

    /**
     * Validate a given self-contained nonce in string form by parsing it and running all appropriate validations.
     * Will cache the nonce once used, so it can not be used again
     *
     * @param nonce to be validated
     * @return True if the nonce is valid and has not been used.
     */
    @Transactional
    public boolean isValidSelfContainedNonce(String nonce) {
        SelfContainedNonce selfContainedNonce;
        try {
            selfContainedNonce = new SelfContainedNonce(nonce, applicationProperties.getNonceLifetimeSeconds(), getNonceSecret());

            if (isNonceRegisteredInCache(selfContainedNonce)) {
                return false;
            }
            saveNonceInCache(selfContainedNonce);
            return true;
        } catch (InvalidNonceException e) {
            return false;
        }
    }

    @Transactional(readOnly = true)
    public boolean isUsedNonce(SelfContainedNonce nonce) {
        return isNonceRegisteredInCache(nonce);
    }

    @Transactional
    public void registerNonce(SelfContainedNonce nonce) {
        saveNonceInCache(nonce);
    }

    @Transactional
    public void invalidateSelfContainedNonce(List<SelfContainedNonce> nonces) {

        if (!nonces.isEmpty()) {
            List<CachedNonce> cachedNonces = nonces.stream()
                    .map(nonce -> new CachedNonce(nonce.getNonceId(), nonce.getNonceInstant()))
                    .toList();
            cachedNonceRepository.saveAll(cachedNonces);
        }
    }

    @Transactional
    @Scheduled(fixedRateString = "${application.nonce-lifetime-seconds}")
    public void cleanNonceCache() {
        cachedNonceRepository.deleteAllOlderThan(
                Instant.now().minus(applicationProperties.getNonceLifetimeSeconds(), ChronoUnit.SECONDS));
    }

    @Cacheable(CacheConfig.ISSUER_SECRET_CACHE)
    public IssuerSecret getNonceSecret() {
        return issuerSecretRepository.findAll().getFirst();
    }

    private void saveNonceInCache(SelfContainedNonce nonce) {
        cachedNonceRepository.save(new CachedNonce(nonce.getNonceId(), nonce.getNonceInstant()));
    }

    private boolean isNonceRegisteredInCache(SelfContainedNonce nonce) {
        return cachedNonceRepository.findById(nonce.getNonceId()).isPresent();
    }
}