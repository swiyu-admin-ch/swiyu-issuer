package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.api.oid4vci.NonceResponseDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.domain.openid.CachedNonce;
import ch.admin.bj.swiyu.issuer.domain.openid.CachedNonceRepository;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.SelfContainedNonce;
import lombok.AllArgsConstructor;
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

    public NonceResponseDto createNonce() {
        return new NonceResponseDto(new SelfContainedNonce().getNonce());
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
        var selfContainedNonce = new SelfContainedNonce(nonce);
        if (!selfContainedNonce.isSelfContainedNonce() || !selfContainedNonce.isValid(applicationProperties.getNonceLifetimeSeconds()) || isNonceRegisteredInCache(selfContainedNonce)) {
            return false;
        }
        saveNonceInCache(selfContainedNonce);
        return true;
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
    public void invalidateSelfContainedNonce(List<String> nonces) {

        var selfContainedNonces = nonces.stream()
                .map(SelfContainedNonce::new)
                .filter(SelfContainedNonce::isSelfContainedNonce)
                .toList();

        if (!selfContainedNonces.isEmpty()) {
            List<CachedNonce> cachedNonces = selfContainedNonces.stream()
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

    private void saveNonceInCache(SelfContainedNonce nonce) {
        cachedNonceRepository.save(new CachedNonce(nonce.getNonceId(), nonce.getNonceInstant()));
    }

    private boolean isNonceRegisteredInCache(SelfContainedNonce nonce) {
        return cachedNonceRepository.findById(nonce.getNonceId()).isPresent();
    }
}