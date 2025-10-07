package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.CacheConfig;
import ch.admin.bj.swiyu.issuer.common.config.CacheCustomizer;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.openid.EncryptionKey;
import ch.admin.bj.swiyu.issuer.domain.openid.EncryptionKeyRepository;
import ch.admin.bj.swiyu.issuer.domain.openid.IssuerEncryptionKeyCache;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerCredentialEncryption;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerCredentialRequestEncryption;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerCredentialResponseEncryption;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHDecrypter;
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
import java.util.UUID;

import static ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError.INVALID_ENCRYPTION_PARAMETERS;

@Service
@RequiredArgsConstructor
public class EncryptionService {

    private final ApplicationProperties applicationProperties;
    private final EncryptionKeyRepository encryptionKeyRepository;
    private final CacheCustomizer cacheCustomizer;
    private final IssuerEncryptionKeyCache keyCache = new IssuerEncryptionKeyCache();

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
                .jwks(keyCache.getPublicEncryptionKeyJWKSetJson())
                .build();
        issuerMetadata.setRequestEncryption(requestEncryption);
        issuerMetadata.setResponseEncryption(IssuerCredentialResponseEncryption.builder().build());
        return issuerMetadata;
    }

    public String decrypt(String encryptedMessage, IssuerMetadata issuerMetadata) {
        try {
            JWEObject encryptedJWT = JWEObject.parse(encryptedMessage);
            JWEHeader header = encryptedJWT.getHeader();
            validateJWEHeaders(header, issuerMetadata.getRequestEncryption());
            JWEDecrypter decrypter = createDecrypter(header);
            encryptedJWT.decrypt(decrypter);
            return encryptedJWT.getPayload().toString();
        } catch (ParseException e) {
            throw new Oid4vcException(e, INVALID_ENCRYPTION_PARAMETERS, "Message is not a correct JWE object");
        } catch (JOSEException e) {
            throw new Oid4vcException(e, INVALID_ENCRYPTION_PARAMETERS, "JWE Object could not be decrypted");
        }
    }

    private void validateJWEHeaders(JWEHeader header, IssuerCredentialEncryption encryptionSpec) {
        if (encryptionSpec == null) {
            throw new Oid4vcException(INVALID_ENCRYPTION_PARAMETERS, "Encryption not supported by issuer metadata");
        }
        if (!encryptionSpec.getEncValuesSupported().contains(header.getEncryptionMethod().toString())) {
            throw new Oid4vcException(INVALID_ENCRYPTION_PARAMETERS, "Unsupported encryption method. Must be one of %s but was %s".formatted(encryptionSpec.getEncValuesSupported(), header.getEncryptionMethod()));
        }
        if (encryptionSpec.getZipValuesSupported() != null && !encryptionSpec.getZipValuesSupported().contains(header.getCompressionAlgorithm().toString())) {
            throw new Oid4vcException(INVALID_ENCRYPTION_PARAMETERS, "Unsupported compression (zip) method. Must be one of %s but was %s".formatted(encryptionSpec.getZipValuesSupported(), header.getCompressionAlgorithm()));
        }
    }

    private JWEDecrypter createDecrypter(JWEHeader header) {
        JWK key = keyCache.getSecretEncryptionKeyJWKSet().getKeyByKeyId(header.getKeyID());
        if (key == null) {
            throw new Oid4vcException(INVALID_ENCRYPTION_PARAMETERS, "Unknown JWK Key Id: " + header.getKeyID());
        }
        if (JWEAlgorithm.Family.ECDH_ES.contains(header.getAlgorithm())) {
            try {
                return new ECDHDecrypter(key.toECKey());
            } catch (JOSEException e) {
                throw new Oid4vcException(e, INVALID_ENCRYPTION_PARAMETERS, "Unsupported Key and Algorithm combination");
            }
        } else {
            throw new Oid4vcException(INVALID_ENCRYPTION_PARAMETERS, "Unsupported Encryption Algorithm");
        }
    }

    private void renewActiveKeySet(List<EncryptionKey> oldEncryptionKeys) {
        JWKSet activeKeySet = createEncryptionKeys();
        keyCache.setPublicEncryptionKeyJWKSetJson(activeKeySet.toJSONObject(true));
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
        keyCache.setSecretEncryptionKeyJWKSet(new JWKSet(activeKeys));
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

    public boolean isRequestEncryptionRequired(IssuerMetadata issuerMetadata) {
        IssuerCredentialRequestEncryption encryptionOptions = issuerMetadata.getRequestEncryption();
        return encryptionOptions != null && encryptionOptions.isEncRequired();
    }
}
