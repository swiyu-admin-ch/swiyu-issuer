package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.CacheConfig;
import ch.admin.bj.swiyu.issuer.common.config.CacheCustomizer;
import ch.admin.bj.swiyu.issuer.domain.openid.EncryptionKey;
import ch.admin.bj.swiyu.issuer.domain.openid.EncryptionKeyRepository;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerCredentialRequestEncryption;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerCredentialResponseEncryption;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.text.ParseException;
import java.time.Instant;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class EncryptionService {

    private final ApplicationProperties applicationProperties;
    private final EncryptionKeyRepository encryptionKeyRepository;
    private final CacheCustomizer cacheCustomizer;
    private Map<String, Object> publicEncryptionKeyJWKSetJson;
    private JWKSet secretEncryptionKeyJWKSet;

    @PostConstruct
    @Scheduled(fixedDelayString = "${application.encryption-key-rotation-interval}")
    @SchedulerLock(name = "rotateEncryptionKeys")
    @Transactional
    public void rotateEncryptionKeys() {
        var encryptionKeys = encryptionKeyRepository.findAll();
        if (encryptionKeys.isEmpty()) {
            // Init
            renewActiveKeySet(encryptionKeys);
        } else {
            // We work with stale keys which are still valid but no more publicized to prevent race condition on holder binding proofs
            Instant staleTime = Instant.now().minus(applicationProperties.getEncryptionKeyRotationInterval());
            // If a key has been stale for the duration a key rotation, it can be safely deleted, as all the holder binding proofs in transmission should have already arrived.
            Instant deleteTime = staleTime.minus(applicationProperties.getEncryptionKeyRotationInterval());
            List<EncryptionKey> deprecatedKeys = encryptionKeys.stream().filter(encryptionKey -> encryptionKey.getCreationTimestamp().isBefore(deleteTime)).toList();
            encryptionKeyRepository.deleteAll(deprecatedKeys);
            // All keys in the database are older than 1 rotation, so no other instance has done a rotation yet.
            boolean keyRotationRequired = encryptionKeys.stream().allMatch(encryptionKey -> encryptionKey.getCreationTimestamp().isBefore(staleTime));
            if (keyRotationRequired) {
                renewActiveKeySet(encryptionKeys);
            }
        }
    }

    /**
     * Overriding issuer metadata encryption options
     */
    @Cacheable(CacheConfig.ISSUER_METADATA_ENCRYPTION_CACHE)
    public IssuerMetadata addEncryptionOptions(IssuerMetadata issuerMetadata) {
        IssuerCredentialRequestEncryption requestEncryption = IssuerCredentialRequestEncryption.builder()
                .jwks(publicEncryptionKeyJWKSetJson)
                .build();
        issuerMetadata.setRequestEncryption(requestEncryption);
        issuerMetadata.setResponseEncryption(IssuerCredentialResponseEncryption.builder().build());
        return issuerMetadata;
    }

    private void renewActiveKeySet(List<EncryptionKey> oldEncryptionKeys) {
        JWKSet activeKeySet = createEncryptionKeys();
        publicEncryptionKeyJWKSetJson = activeKeySet.toJSONObject(true);
        List<JWK> activeKeys = new LinkedList<>(activeKeySet.getKeys());
        oldEncryptionKeys.stream()
                .map(EncryptionKey::getJwks)
                .map(jwksJson -> {
                    try {
                        return JWKSet.parse(jwksJson);
                    } catch (ParseException e) {
                        throw new IllegalStateException("Saved encryption keys can not be parsed", e);
                    }
                })
                .map(JWKSet::getKeys)
                .forEach(activeKeys::addAll);
        secretEncryptionKeyJWKSet = new JWKSet(activeKeys);
        cacheCustomizer.emptyIssuerMetadataEncryptionCache();
    }

    private JWKSet createEncryptionKeys() {
        try {
            ECKey ephemeralEncryptionKey = new ECKeyGenerator(Curve.P_256).keyID(UUID.randomUUID().toString()).generate();
            JWKSet jwks = new JWKSet(ephemeralEncryptionKey);
            EncryptionKey key = EncryptionKey
                    .builder()
                    .id(UUID.randomUUID())
                    .jwks(jwks.toJSONObject(false))
                    .creationTimestamp(Instant.now())
                    .build();
            encryptionKeyRepository.save(key);
            return jwks;
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }
}
