package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.CacheConfig;
import ch.admin.bj.swiyu.issuer.common.config.CacheCustomizer;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.openid.EncryptionKey;
import ch.admin.bj.swiyu.issuer.domain.openid.EncryptionKeyRepository;
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
import java.util.*;

import static ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError.INVALID_ENCRYPTION_PARAMETERS;

/**
 * Decryption Method and creation and rotation of ephemeral encryption keys
 */
@Service
@RequiredArgsConstructor
public class EncryptionService {

    private final ApplicationProperties applicationProperties;
    private final EncryptionKeyRepository encryptionKeyRepository;
    private final CacheCustomizer cacheCustomizer;
    private final IssuerMetadata issuerMetadata;

    /**
     * Performs a key rotation for the encryption keys, replacing the currently active key set.
     * Will keep one time unit of deprecated keys to prevent race conditions with credential requests.
     */
    @PostConstruct
    @Scheduled(fixedDelayString = "${application.encryption-key-rotation-interval}")
    @SchedulerLock(name = "rotateEncryptionKeys")
    @Transactional
    public void rotateEncryptionKeys() {
        var encryptionKeys = encryptionKeyRepository.findAll();
        if (encryptionKeys.isEmpty()) {
            // Init with a new set of encryption keys
            createNewKeys();
        } else {
            // We work with stale keys which are still valid but no more publicized to prevent race condition on holder binding proofs
            Instant staleTime = keyRotationInstant(Instant.now());
            // If a key has been stale for the duration a key rotation, it can be safely deleted, as all the holder binding proofs in transmission should have already arrived.
            Instant deleteTime = keyRotationInstant(staleTime);
            List<EncryptionKey> deprecatedKeys = encryptionKeys.stream()
                    .filter(encryptionKey -> encryptionKey.getCreationTimestamp()
                            .isBefore(deleteTime))
                    .toList();
            encryptionKeyRepository.deleteAll(deprecatedKeys);
            // All keys in the database are older than 1 rotation, so no other instance has done a rotation yet.
            boolean keyRotationRequired = encryptionKeys.stream()
                    .allMatch(encryptionKey -> encryptionKey.getCreationTimestamp()
                            .isBefore(staleTime));
            if (keyRotationRequired) {
                createNewKeys();
            }
        }
    }

    /**
     * Overriding bean issuer metadata encryption options with supported values.
     */
    @Transactional(readOnly = true)
    @Cacheable(CacheConfig.ISSUER_METADATA_ENCRYPTION_CACHE)
    public IssuerMetadata issuerMetadataWithEncryptionOptions() {
        IssuerCredentialRequestEncryption requestEncryption = IssuerCredentialRequestEncryption.builder()
                .jwks(getActivePublicKeys())
                .encRequired(applicationProperties.isEncryptionEnforce())
                .build();
        issuerMetadata.setRequestEncryption(requestEncryption);
        issuerMetadata.setResponseEncryption(IssuerCredentialResponseEncryption.builder()
                .encRequired(applicationProperties.isEncryptionEnforce())
                .build());
        return issuerMetadata;
    }

    /**
     * @param encryptedMessage JWE encrypted object serialized as string
     * @return the decrypted object
     * @throws Oid4vcException if the object could not be decrypted
     */
    @Transactional(readOnly = true)
    public String decrypt(String encryptedMessage) {
        try {
            JWEObject encryptedJWT = JWEObject.parse(encryptedMessage);
            JWEHeader header = encryptedJWT.getHeader();
            validateJWEHeaders(header, issuerMetadata.getRequestEncryption());
            JWEDecrypter decrypter = createDecrypter(header);
            encryptedJWT.decrypt(decrypter);
            return encryptedJWT.getPayload()
                    .toString();
        } catch (ParseException e) {
            throw new Oid4vcException(e, INVALID_ENCRYPTION_PARAMETERS, "Message is not a correct JWE object");
        } catch (JOSEException e) {
            throw new Oid4vcException(e, INVALID_ENCRYPTION_PARAMETERS, "JWE Object could not be decrypted");
        }
    }

    /**
     * @return true, if credential requests MUST be encrypted
     */
    public boolean isRequestEncryptionMandatory() {
        IssuerCredentialRequestEncryption encryptionOptions = issuerMetadata.getRequestEncryption();
        return encryptionOptions != null && encryptionOptions.isEncRequired();
    }

    /**
     * Creates a new ephemeral key set.
     */
    private void createNewKeys() {
        try {
            ECKey ephemeralEncryptionKey = new ECKeyGenerator(Curve.P_256).keyID(UUID.randomUUID()
                            .toString())
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

    private Instant keyRotationInstant(Instant instant) {
        return instant.minus(applicationProperties.getEncryptionKeyRotationInterval());
    }

    /**
     * Get the set of currently active public keys to be used for example by the holder for credential request encryption
     *
     * @return a JWESet compatible Map
     */
    private Map<String, Object> getActivePublicKeys() {
        List<EncryptionKey> allKeys = encryptionKeyRepository.findAll();
        Instant staleTime = keyRotationInstant(Instant.now());
        // Pick newest key that is still within active window (explicit ordering to avoid relying on DB/list iteration order)
        return allKeys.stream()
                .filter(k -> k.getCreationTimestamp().isAfter(staleTime))
                .max(Comparator.comparing(EncryptionKey::getCreationTimestamp))
                .orElseThrow(() -> new IllegalStateException("No active encryption key available (rotation window exceeded)"))
                .getJwkSet()
                .toJSONObject(true); // public only
    }

    /**
     * ensures the JWEHeader uses the properties required in the issuer metadata
     *
     * @param header         header to be validated
     * @param encryptionSpec Credential encryption spec published in the issuer metadata
     */
    private void validateJWEHeaders(JWEHeader header, IssuerCredentialEncryption encryptionSpec) {
        if (encryptionSpec == null) {
            throw new Oid4vcException(INVALID_ENCRYPTION_PARAMETERS, "Encryption not supported by issuer metadata");
        }
        if (!encryptionSpec.getEncValuesSupported()
                .contains(header.getEncryptionMethod()
                        .toString())) {
            throw new Oid4vcException(INVALID_ENCRYPTION_PARAMETERS,
                    "Unsupported encryption method. Must be one of %s but was %s".formatted(encryptionSpec.getEncValuesSupported(),
                            header.getEncryptionMethod()));
        }
        if (encryptionSpec.getZipValuesSupported() != null && !encryptionSpec.getZipValuesSupported()
                .contains(header.getCompressionAlgorithm()
                        .toString())) {
            throw new Oid4vcException(INVALID_ENCRYPTION_PARAMETERS,
                    "Unsupported compression (zip) method. Must be one of %s but was %s".formatted(encryptionSpec.getZipValuesSupported(),
                            header.getCompressionAlgorithm()));
        }
    }

    /**
     * Creates a nimbus JWEDecrypter using key information encoded in the JWE header
     *
     * @param header JWEHeader holding key information
     * @return a JWEDecrypter compatible to the JWEHeader provided
     * @throws Oid4vcException if an unknown key or unsupported algorithm was used in the JWEHeader
     */
    private JWEDecrypter createDecrypter(JWEHeader header) {
        JWK key = getActivePrivateKeys().getKeyByKeyId(header.getKeyID());
        if (key == null) {
            throw new Oid4vcException(INVALID_ENCRYPTION_PARAMETERS, "Unknown JWK Key Id: " + header.getKeyID());
        }
        if (JWEAlgorithm.Family.ECDH_ES.contains(header.getAlgorithm())) {
            try {
                return new ECDHDecrypter(key.toECKey());
            } catch (JOSEException e) {
                throw new Oid4vcException(e,
                        INVALID_ENCRYPTION_PARAMETERS,
                        "Unsupported Key and Algorithm combination");
            }
        } else {
            throw new Oid4vcException(INVALID_ENCRYPTION_PARAMETERS, "Unsupported Encryption Algorithm");
        }
    }

    /**
     * Get all currently valid encryption private keys. Contains the previous private key set
     *
     * @return JWKSet with the combined encryption private keys
     */
    private JWKSet getActivePrivateKeys() {
        List<EncryptionKey> allKeys = encryptionKeyRepository.findAll();
        return new JWKSet(allKeys.stream()
                .map(EncryptionKey::getJwkSet)
                .map(JWKSet::getKeys)
                .flatMap(Collection::stream)
                .toList());
    }

}
