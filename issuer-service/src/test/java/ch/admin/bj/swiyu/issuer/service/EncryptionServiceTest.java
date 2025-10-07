package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.CacheCustomizer;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.openid.EncryptionKey;
import ch.admin.bj.swiyu.issuer.domain.openid.EncryptionKeyRepository;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.assertj.core.api.Assertions.*;

class EncryptionServiceTest {
    static final Duration KEY_ROTATION_INTERVAL = Duration.ofSeconds(10);
    private EncryptionService encryptionService;
    private EncryptionKeyRepository encryptionKeyRepository;
    private List<EncryptionKey> encryptionKeyTestCache;

    @BeforeEach
    void setUp() {
        setupMockRepository();
        ApplicationProperties applicationProperties = Mockito.mock(ApplicationProperties.class);
        encryptionService = new EncryptionService(
                applicationProperties,
                encryptionKeyRepository,
                new CacheCustomizer()
        );
        Mockito.when(applicationProperties.getEncryptionKeyRotationInterval()).thenReturn(KEY_ROTATION_INTERVAL);
        // Mock @PostConstruction
        encryptionService.rotateEncryptionKeys();
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
        Mockito.when(encryptionKeyRepository.findAll()).thenReturn(encryptionKeyTestCache);
    }


    @Test
    void testAddEncryptionOptions() {
        IssuerMetadata issuerMetadata = new IssuerMetadata();
        encryptionService.addEncryptionOptions(issuerMetadata);
        assertThat(issuerMetadata.getRequestEncryption()).isNotNull();
        assertThat(issuerMetadata.getResponseEncryption()).isNotNull();
        var requestEncryption = issuerMetadata.getRequestEncryption();
        var responseEncryption = issuerMetadata.getResponseEncryption();
        for (var encryptionSpec : List.of(requestEncryption, responseEncryption)) {
            assertThat(encryptionSpec.getEncValuesSupported()).contains("A128GCM");
            assertThat(encryptionSpec.getZipValuesSupported()).contains("DEF");

        }
    }

    @Test
    void testKeyRotation() {
        IssuerMetadata issuerMetadata = new IssuerMetadata();
        encryptionService.addEncryptionOptions(issuerMetadata);

        var jwks = assertDoesNotThrow(() -> JWKSet.parse(issuerMetadata.getRequestEncryption().getJwks()));
        triggerKeyRotation();
        encryptionService.addEncryptionOptions(issuerMetadata);
        var updatedRequestEncryption = issuerMetadata.getRequestEncryption();
        var updatedJwks = assertDoesNotThrow(() -> JWKSet.parse(updatedRequestEncryption.getJwks()));
        // Should not have any public keys
        assertThat(jwks.containsNonPublicKeys()).isFalse();
        assertThat(updatedJwks.containsNonPublicKeys()).isFalse();

        var keyIds = jwks.getKeys().stream().map(JWK::getKeyID).toList();
        var updatedKeyIds = updatedJwks.getKeys().stream().map(JWK::getKeyID).toList();
        // Should not begin to have more keys
        assertEquals(keyIds.size(), updatedKeyIds.size());
        // should not have any of the same keys after rotation publicized
        assertFalse(updatedKeyIds.stream().anyMatch(keyIds::contains));

        var allKeys = new LinkedList<>(jwks.getKeys());
        allKeys.addAll(updatedJwks.getKeys());
        // Both key sets should be valid for decryption
        var encryptedTestMessage = "Hello World";
        for (var key : allKeys) {
            var encrypted = assertDoesNotThrow(() -> createEncrytpedMessage(encryptedTestMessage, key));
            var decrypted = assertDoesNotThrow(() -> encryptionService.decrypt(encrypted, issuerMetadata));
            assertEquals(encryptedTestMessage, decrypted);
        }
    }

    private void triggerKeyRotation() {
        timePasses();
        assertDoesNotThrow(encryptionService::rotateEncryptionKeys);
    }

    private void timePasses() {
        for (var encryptionKey : encryptionKeyTestCache) {
            encryptionKey.setCreationTimestamp(encryptionKey.getCreationTimestamp().minus(KEY_ROTATION_INTERVAL).minusMillis(100));
        }
    }

    @Test
    void testDeprecateKeys() {
        //Setup
        IssuerMetadata issuerMetadata = new IssuerMetadata();
        encryptionService.addEncryptionOptions(issuerMetadata);
        var deprecatedJwks = assertDoesNotThrow(() -> JWKSet.parse(issuerMetadata.getRequestEncryption().getJwks()));
        triggerKeyRotation();
        encryptionService.addEncryptionOptions(issuerMetadata);
        var oldJwks = assertDoesNotThrow(() -> JWKSet.parse(issuerMetadata.getRequestEncryption().getJwks()));

        // Deprecate old keys by setting date to past
        var deprectatedKey = encryptionKeyTestCache.getFirst();
        deprectatedKey.setCreationTimestamp(Instant.now().minus(Duration.ofSeconds(20)));
        ArgumentCaptor<Iterable> deleteCallCaptor = ArgumentCaptor.forClass(Iterable.class);
        Mockito.doAnswer(invocation -> {
            encryptionKeyTestCache.remove(deprectatedKey);
            return null;
        }).when(encryptionKeyRepository).deleteAll(deleteCallCaptor.capture());
        // Rotate keys
        triggerKeyRotation();
        var deletedValues = (List)deleteCallCaptor.getValue();
        assertThat(deletedValues).hasSize(1).contains(deprectatedKey);


        encryptionService.addEncryptionOptions(issuerMetadata);
        var jwks = assertDoesNotThrow(() -> JWKSet.parse(issuerMetadata.getRequestEncryption().getJwks()));
        for (var deprecatedKey : deprecatedJwks.getKeys()) {
            var encrypted = assertDoesNotThrow(() -> createEncrytpedMessage("hello world", deprecatedKey));
            assertThrows(Oid4vcException.class, () -> encryptionService.decrypt(encrypted, issuerMetadata));
        }
        var validKeys = new LinkedList<>(oldJwks.getKeys());
        validKeys.addAll(jwks.getKeys());
        for (var key :  validKeys) {
            var encrypted = assertDoesNotThrow(() -> createEncrytpedMessage("hello world", key));
            assertDoesNotThrow(() -> encryptionService.decrypt(encrypted, issuerMetadata));
        }
    }

    private String createEncrytpedMessage(String encryptedTestMessage, JWK key) throws JOSEException {
        ECDHEncrypter encrypter = new ECDHEncrypter(key.toECKey());
        JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, EncryptionMethod.A128GCM)
                        .compressionAlgorithm(CompressionAlgorithm.DEF)
                        .keyID(key.getKeyID())
                        .build(),
                new Payload(encryptedTestMessage)
        );
        jweObject.encrypt(encrypter);
        return jweObject.serialize();
    }
}
