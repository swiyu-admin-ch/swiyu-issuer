package ch.admin.bj.swiyu.issuer.service.enc;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.CacheCustomizer;
import ch.admin.bj.swiyu.issuer.domain.openid.EncryptionKey;
import ch.admin.bj.swiyu.issuer.domain.openid.EncryptionKeyRepository;
import ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Manages creation, rotation, and retrieval of ephemeral encryption keys.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class EncryptionKeyService {

    private final ApplicationProperties applicationProperties;
    private final EncryptionKeyRepository encryptionKeyRepository;
    private final CacheCustomizer cacheCustomizer;

    /**
     * Performs a key rotation for the encryption keys, replacing the currently active key set.
     * Will keep one time unit of deprecated keys to prevent race conditions with credential requests.
     *
     * @return true if a new encryption key was generated, otherwise false
     */
    @Transactional
    public boolean rotateEncryptionKeys() {
        boolean newKeyGenerated = false;
        var encryptionKeys = encryptionKeyRepository.findAll();
        if (encryptionKeys.isEmpty()) {
            createNewKeys();
            log.info("Initial encryption keys created");
            newKeyGenerated = true;
        } else {
            Instant staleTime = getStaleTime();
            Instant deleteTime = getDeleteTime();
            List<EncryptionKey> deprecatedKeys = encryptionKeys.stream()
                    .filter(encryptionKey -> encryptionKey.getCreationTimestamp().isBefore(deleteTime))
                    .toList();
            encryptionKeyRepository.deleteAll(deprecatedKeys);
            log.debug("{} deprecated ephemeral encryption Keys deleted", deprecatedKeys.size());

            boolean keyRotationRequired = encryptionKeys.stream()
                    .allMatch(encryptionKey -> encryptionKey.getCreationTimestamp().isBefore(staleTime));
            if (keyRotationRequired) {
                log.info("New Encryption keys created");
                createNewKeys();
                newKeyGenerated = true;
            }
        }
        return newKeyGenerated;
    }

    /**
     * Get the set of currently active public keys to be used for example by the holder for credential request encryption.
     *
     * @return a JWESet compatible Map
     */
    @Transactional(readOnly = true)
    public Map<String, Object> getActivePublicKeys() {
        List<EncryptionKey> allKeys = encryptionKeyRepository.findAll();
        Instant deprecateTime = getDeleteTime();
        return allKeys.stream()
                .filter(k -> k.getCreationTimestamp().isAfter(deprecateTime))
                .max(Comparator.comparing(EncryptionKey::getCreationTimestamp))
                .orElseThrow(() -> new Oid4vcException(CredentialRequestError.INVALID_ENCRYPTION_PARAMETERS, "No active encryption key available (rotation window exceeded)"))
                .getJwkSet()
                .toJSONObject(true);
    }

    /**
     * Get all currently valid encryption private keys. Contains the previous private key set.
     *
     * @return JWKSet with the combined encryption private keys
     */
    @Transactional(readOnly = true)
    JWKSet getActivePrivateKeys() {
        List<EncryptionKey> allKeys = encryptionKeyRepository.findAll();
        return new JWKSet(allKeys.stream()
                .map(EncryptionKey::getJwkSet)
                .map(JWKSet::getKeys)
                .flatMap(Collection::stream)
                .toList());
    }

    private void createNewKeys() {
        try {
            log.debug("Create new ephemeral encryption key");
            ECKey ephemeralEncryptionKey = new ECKeyGenerator(Curve.P_256)
                    .algorithm(new Algorithm("ECDH-ES"))
                    .keyID(UUID.randomUUID().toString())
                    .generate();
            JWKSet jwks = new JWKSet(ephemeralEncryptionKey);
            EncryptionKey key = EncryptionKey.builder()
                    .id(UUID.randomUUID())
                    .jwks(jwks.toJSONObject(false))
                    .creationTimestamp(Instant.now())
                    .build();
            encryptionKeyRepository.save(key);
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
        cacheCustomizer.emptyIssuerMetadataEncryptionCache();
    }

    /**
     * Returns the timestamp before which encryption keys are considered expired and can be deleted.
     *
     * @return Instant before which keys are deleted
     */
    private Instant getDeleteTime() {
        return keyRotationInstant(keyRotationInstant(Instant.now()));
    }

    /**
     * Returns the timestamp before which encryption keys are considered stale and should not be used for new operations.
     *
     * @return Instant before which keys are stale
     */
    private Instant getStaleTime() {
        return keyRotationInstant(Instant.now());
    }

    private Instant keyRotationInstant(Instant instant) {
        return instant.minus(applicationProperties.getEncryptionKeyRotationInterval());
    }
}
