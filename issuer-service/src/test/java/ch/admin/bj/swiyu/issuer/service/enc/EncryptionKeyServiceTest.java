package ch.admin.bj.swiyu.issuer.service.enc;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.CacheCustomizer;
import ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.openid.EncryptionKey;
import ch.admin.bj.swiyu.issuer.domain.openid.EncryptionKeyRepository;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Exercises {@link EncryptionKeyService} key lifecycle behavior:
 */
class EncryptionKeyServiceTest {
    static final Duration KEY_ROTATION_INTERVAL = Duration.ofSeconds(10);
    private EncryptionKeyRepository encryptionKeyRepository;
    private EncryptionKeyService encryptionKeyService;
    private List<EncryptionKey> encryptionKeyTestCache;

    @BeforeEach
    void setUp() {
        setupMockRepository();
        ApplicationProperties applicationProperties = Mockito.mock(ApplicationProperties.class);
        encryptionKeyService = new EncryptionKeyService(applicationProperties, encryptionKeyRepository, new CacheCustomizer());
        Mockito.when(applicationProperties.getEncryptionKeyRotationInterval())
                .thenReturn(KEY_ROTATION_INTERVAL);
        encryptionKeyService.rotateEncryptionKeys();
    }

    @Test
    // Rotation produces new keys while keeping decryption possible with both old and new keys in the overlap window
    void shouldAllowDecryptionWithBothOldAndNewKeysAfterRotation() throws JOSEException, ParseException {
        var jwks = JWKSet.parse(encryptionKeyService.getActivePublicKeys());
        triggerKeyRotation();
        var updatedJwks = JWKSet.parse(encryptionKeyService.getActivePublicKeys());

        assertThat(jwks.containsNonPublicKeys()).isFalse();
        assertThat(updatedJwks.containsNonPublicKeys()).isFalse();
        assertThat(updatedJwks.getKeys()).doesNotContainAnyElementsOf(jwks.getKeys());
        assertEquals(jwks.getKeys().size(), updatedJwks.getKeys().size());

        var allKeys = new LinkedList<>(jwks.getKeys());
        allKeys.addAll(updatedJwks.getKeys());
        String payload = "Hello World";
        for (var key : allKeys) {
            String encrypted = createEncryptedMessage(payload, key);
            assertEquals(payload, decryptWithKeySet(encryptionKeyService.getActivePrivateKeys(), encrypted));
        }
    }

    @Test
    // Even when the newest key is stale, publishing public keys should not throw
    void shouldNotThrowWhenPublishingPublicKeysWithStaleActiveKey() {
        triggerKeyRotation();
        timePasses();
        assertDoesNotThrow(encryptionKeyService::getActivePublicKeys);
    }

    @Test
    // Once all keys fall outside the validity window, fetching active public keys should fail
    void failsWhenNoKeysWithinWindow() {
        triggerKeyRotation();
        timePasses();
        timePasses();
        assertThrows(Oid4vcException.class, encryptionKeyService::getActivePublicKeys);
    }

    @Test
    // Deprecated keys are deleted and cannot decrypt; still-valid keys remain usable
    void shouldDeleteDeprecatedKeysAndPreserveValidKeys() throws ParseException, JOSEException {
        var deprecatedJwks = JWKSet.parse(encryptionKeyService.getActivePublicKeys());
        triggerKeyRotation();
        var oldJwks = JWKSet.parse(encryptionKeyService.getActivePublicKeys());

        var deprecatedKeyEntity = encryptionKeyTestCache.getFirst();
        deprecatedKeyEntity.setCreationTimestamp(Instant.now().minus(Duration.ofSeconds(20)));
        ArgumentCaptor<Iterable> deleteCallCaptor = ArgumentCaptor.forClass(Iterable.class);
        Mockito.doAnswer(invocation -> {
                    encryptionKeyTestCache.remove(deprecatedKeyEntity);
                    return null;
                })
                .when(encryptionKeyRepository)
                .deleteAll(deleteCallCaptor.capture());

        triggerKeyRotation();
        var deletedValues = (List) deleteCallCaptor.getValue();
        assertThat(deletedValues).hasSize(1).contains(deprecatedKeyEntity);

        var jwks = JWKSet.parse(encryptionKeyService.getActivePublicKeys());
        for (var deprecatedKey : deprecatedJwks.getKeys()) {
            String encrypted = createEncryptedMessage("hello world", deprecatedKey);
            assertThrows(Oid4vcException.class, () -> decryptWithKeySet(encryptionKeyService.getActivePrivateKeys(), encrypted));
        }
        var validKeys = new LinkedList<>(oldJwks.getKeys());
        validKeys.addAll(jwks.getKeys());
        for (var key : validKeys) {
            String encrypted = createEncryptedMessage("hello world", key);
            assertDoesNotThrow(() -> decryptWithKeySet(encryptionKeyService.getActivePrivateKeys(), encrypted));
        }
    }

    private void setupMockRepository() {
        encryptionKeyTestCache = new LinkedList<>();
        encryptionKeyRepository = Mockito.mock(EncryptionKeyRepository.class);
        Mockito.when(encryptionKeyRepository.save(Mockito.any(EncryptionKey.class)))
                .then(invocationOnMock -> {
                    EncryptionKey savedObject = invocationOnMock.getArgument(0);
                    encryptionKeyTestCache.add(savedObject);
                    return savedObject;
                });
        Mockito.when(encryptionKeyRepository.findAll())
                .thenReturn(encryptionKeyTestCache);
    }

    private void triggerKeyRotation() {
        timePasses();
        assertDoesNotThrow(encryptionKeyService::rotateEncryptionKeys);
    }

    private void timePasses() {
        for (var encryptionKey : encryptionKeyTestCache) {
            encryptionKey.setCreationTimestamp(encryptionKey.getCreationTimestamp()
                    .minus(KEY_ROTATION_INTERVAL)
                    .minusMillis(100));
        }
    }

    private String createEncryptedMessage(String message, JWK key) throws JOSEException {
        ECDHEncrypter encrypter = new ECDHEncrypter(key.toECKey());
        JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A128GCM)
                        .compressionAlgorithm(CompressionAlgorithm.DEF)
                        .keyID(key.getKeyID())
                        .build(),
                new Payload(message)
        );
        jweObject.encrypt(encrypter);
        return jweObject.serialize();
    }

    private String decryptWithKeySet(JWKSet keys, String encrypted) {
        try {
            JWEObject jweObject = JWEObject.parse(encrypted);
            JWK key = keys.getKeyByKeyId(jweObject.getHeader().getKeyID());
            if (key == null) {
                throw new Oid4vcException(CredentialRequestError.CREDENTIAL_REQUEST_DENIED, "Unknown key");
            }
            JWEDecrypter decrypter = new com.nimbusds.jose.crypto.ECDHDecrypter(key.toECKey());
            jweObject.decrypt(decrypter);
            return jweObject.getPayload().toString();
        } catch (Exception e) {
            if (e instanceof Oid4vcException) {
                throw (Oid4vcException) e;
            }
            throw new RuntimeException(e);
        }
    }
}
