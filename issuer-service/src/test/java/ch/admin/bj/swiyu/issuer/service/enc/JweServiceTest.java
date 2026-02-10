package ch.admin.bj.swiyu.issuer.service.enc;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.CacheCustomizer;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.openid.EncryptionKey;
import ch.admin.bj.swiyu.issuer.domain.openid.EncryptionKeyRepository;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerCredentialRequestEncryption;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.time.Duration;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies JWE-facing behavior of {@link JweService}:
 */
class JweServiceTest {
    static final Duration KEY_ROTATION_INTERVAL = Duration.ofSeconds(10);
    private JweService jweService;
    private EncryptionKeyRepository encryptionKeyRepository;
    private EncryptionKeyService encryptionKeyService;
    private List<EncryptionKey> encryptionKeyTestCache;
    private IssuerMetadata issuerMetadata;

    @BeforeEach
    void setUp() {
        setupMockRepository();
        ApplicationProperties applicationProperties = Mockito.mock(ApplicationProperties.class);
        issuerMetadata = IssuerMetadata.builder()
            .requestEncryption(IssuerCredentialRequestEncryption.builder()
                .encRequired(true)
                .build())
            .build();
        encryptionKeyService = new EncryptionKeyService(applicationProperties, encryptionKeyRepository, new CacheCustomizer());
        jweService = new JweService(applicationProperties, issuerMetadata, encryptionKeyService);
        Mockito.when(applicationProperties.getEncryptionKeyRotationInterval())
                .thenReturn(KEY_ROTATION_INTERVAL);
        encryptionKeyService.rotateEncryptionKeys();
    }

    @Test
    // Ensures issuer metadata exposes supported enc/zip values populated by the service
    void testIssuerMetadataWithEncryptionOptions() {
        jweService.issuerMetadataWithEncryptionOptions();
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
    // Verifies decrypt succeeds when using an active key from the published JWKS
    void decryptsWithActiveKey() {
        jweService.issuerMetadataWithEncryptionOptions();
        var jwks = assertDoesNotThrow(() -> JWKSet.parse(issuerMetadata.getRequestEncryption().getJwks()));
        var activeKey = jwks.getKeys().getFirst();

        String plaintext = "Hello World";
        String encrypted = assertDoesNotThrow(() -> createEncryptedMessage(plaintext, activeKey));
        String decrypted = assertDoesNotThrow(() -> jweService.decrypt(encrypted));
        assertEquals(plaintext, decrypted);
    }

    @Test
    // Confirms decryption fails for a JWE encrypted with an unknown/foreign key ID
    void rejectsUnknownKeyId() throws JOSEException {
        jweService.issuerMetadataWithEncryptionOptions();
        ECKey foreignKey = new ECKeyGenerator(Curve.P_256)
                .algorithm(new Algorithm("ECDH-ES"))
                .keyID(UUID.randomUUID().toString())
                .generate();
        String encrypted = createEncryptedMessage("Hello", foreignKey);
        assertThrows(Oid4vcException.class, () -> jweService.decrypt(encrypted));
    }

    @Test
    void rejectMissingEncryption() {
        assertThrows(Oid4vcException.class, () -> jweService.decryptRequest("Anything", "application/json"));
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
}
