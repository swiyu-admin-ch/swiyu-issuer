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

@Service
@AllArgsConstructor
public class NonceService {
    private final ApplicationProperties applicationProperties;
    private final CachedNonceRepository cachedNonceRepository;

    public NonceResponseDto createNonce(){
        return new NonceResponseDto(new SelfContainedNonce().getNonce());
    }

    @Transactional(readOnly = true)
    public boolean isUsedNonce(SelfContainedNonce nonce) {
        return cachedNonceRepository.findById(nonce.getNonceId()).isPresent();
    }

    @Transactional
    public void registerNonce(SelfContainedNonce nonce) {
        cachedNonceRepository.save(new CachedNonce(nonce.getNonceId(), nonce.getNonceInstant()));
    }

    @Transactional
    @Scheduled(fixedRateString = "${application.nonce-lifetime-seconds}")
    public void cleanNonceCache() {
        cachedNonceRepository.deleteAllOlderThan(
                Instant.now().minus(applicationProperties.getNonceLifetimeSeconds(), ChronoUnit.SECONDS));
    }
}
