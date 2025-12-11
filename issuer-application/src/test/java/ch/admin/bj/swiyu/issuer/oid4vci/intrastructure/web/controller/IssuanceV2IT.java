package ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.oid4vci.test.TestInfrastructureUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.stream.IntStream;

import static ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller.IssuanceV2TestUtils.*;
import static ch.admin.bj.swiyu.issuer.oid4vci.test.CredentialOfferTestData.*;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.doReturn;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
@Transactional
class IssuanceV2IT {

    private final UUID validPreAuthCode = UUID.randomUUID();
    private final UUID validUnboundPreAuthCode = UUID.randomUUID();
    private StatusList testStatusList;
    private CredentialManagement credentialManagement;
    private List<ECKey> holderKeys;
    @Autowired
    private MockMvc mock;
    @Autowired
    private StatusListRepository statusListRepository;
    @Autowired
    private CredentialOfferStatusRepository credentialOfferStatusRepository;
    @Autowired
    private CredentialOfferRepository credentialOfferRepository;
    @Autowired
    private ApplicationProperties applicationProperties;
    @Autowired
    private SdjwtProperties sdjwtProperties;
    @Autowired
    private ObjectMapper objectMapper;
    @MockitoSpyBean
    private IssuerMetadata issuerMetadata;
    @Autowired
    private CredentialManagementRepository credentialManagementRepository;

    @BeforeEach
    void setUp() {
        testStatusList = saveStatusList(createStatusList());
        CredentialOffer offer = createTestOffer(validPreAuthCode, CredentialOfferStatusType.OFFERED, "university_example_sd_jwt");
        saveStatusListLinkedOffer(offer, testStatusList, 0);
        holderKeys = IntStream.range(0, issuerMetadata.getIssuanceBatchSize())
                .boxed()
                .map(i -> assertDoesNotThrow(() -> createPrivateKeyV2("Test-Key-%s".formatted(i))))
                .toList();

        var unboundOffer = createTestOffer(validUnboundPreAuthCode, CredentialOfferStatusType.OFFERED, "unbound_example_sd_jwt");
        saveStatusListLinkedOffer(unboundOffer, testStatusList, 1);
    }

    @Test
    void testSdJwtOffer_withProof_thenSuccess() throws Exception {

        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");
        var credentialRequestString = getCredentialRequestStringV2(mock, holderKeys, applicationProperties);

        var response = requestCredentialV2(mock, (String) token, credentialRequestString)
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/json"))
                .andExpect(jsonPath("$.credentials").isNotEmpty())
                .andExpect(jsonPath("$.transaction_id").doesNotExist())
                .andExpect(jsonPath("$.interval").doesNotExist())
                .andReturn();

        var credentials = extractCredentialsV2(response);

        assertEquals(issuerMetadata.getIssuanceBatchSize(), credentials.size());
        var credential = credentials.get(0).getAsJsonObject();
        var credentialString = credential.get("credential").getAsString();
        testHolderBindingV2(credentialString, holderKeys.get(0));
    }

    @Test
    void testSdJwtOffer_withMetadata_thenSuccess() throws Exception {

        var validPreAuthCodeWithMetadata = UUID.randomUUID();
        var vctIntegrity = "vct#integrity";
        var vctMetadataUri = "vct_metadata_uri";
        var vctMetadataUriIntegrity = "vct_metadata_uri#integrity";

        var metadata = new CredentialOfferMetadata(false, vctIntegrity, vctMetadataUri, vctMetadataUriIntegrity);
        var getValidPreAuthCodeWithMetadataOffer = createTestOffer(validPreAuthCodeWithMetadata, CredentialOfferStatusType.OFFERED, "university_example_sd_jwt", metadata);
        saveStatusListLinkedOffer(getValidPreAuthCodeWithMetadataOffer, testStatusList, 2);

        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validPreAuthCodeWithMetadata.toString());
        var token = tokenResponse.get("access_token");
        var credentialRequestString = getCredentialRequestStringV2(mock, holderKeys, applicationProperties);

        var response = requestCredentialV2(mock, (String) token, credentialRequestString)
                .andExpect(status().isOk())
                .andReturn();

        var credentials = extractCredentialsV2(response);

        assertEquals(issuerMetadata.getIssuanceBatchSize(), credentials.size());
        var credential = credentials.get(0).getAsJsonObject();
        var credentialString = credential.get("credential").getAsString();
        var claims = getVcClaims(credentialString);

        assertEquals(vctIntegrity, claims.get(vctIntegrity).getAsString());
        assertEquals(vctMetadataUri, claims.get(vctMetadataUri).getAsString());
        assertEquals(vctMetadataUriIntegrity, claims.get(vctMetadataUriIntegrity).getAsString());
    }

    @Test
    void testSdJwtOffer_withoutProof_thenSuccess() throws Exception {

        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validUnboundPreAuthCode.toString());
        var token = tokenResponse.get("access_token");
        var credentialRequestString = String.format("{\"credential_configuration_id\": \"%s\"}",
                "unbound_example_sd_jwt");

        // assumption if no proofs provided then only 1 credential is issued
        var response = requestCredentialV2(mock, (String) token, credentialRequestString)
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/json"))
                .andExpect(jsonPath("$.credentials").isNotEmpty())
                .andExpect(jsonPath("$.transaction_id").doesNotExist())
                .andExpect(jsonPath("$.interval").doesNotExist())
                .andReturn();

        var credentials = extractCredentialsV2(response);

        // without proof also configured batch size credential is issued
        assertEquals(issuerMetadata.getIssuanceBatchSize(), credentials.size());
    }

    @Test
    void testSdJwtOffer_withRequestAndResponseEncryption_thenSuccess() throws Exception {

        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");

        // Fetch issuer metadata for encryption info
        var metadata = assertDoesNotThrow(() -> objectMapper.readValue(mock.perform(get("/oid4vci/.well-known/openid-credential-issuer"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString(), IssuerMetadata.class));

        // Response Encryption
        assertThat(metadata.getResponseEncryption()).isNotNull();
        assertTrue(metadata.getResponseEncryption().getAlgValuesSupported().contains(JWEAlgorithm.ECDH_ES.getName()));
        assertTrue(metadata.getResponseEncryption().getEncValuesSupported().contains(EncryptionMethod.A128GCM.getName()));
        ECKey encryptionKey = new ECKeyGenerator(Curve.P_256)
                .keyID("transportEncKeyEC")
                .keyUse(KeyUse.ENCRYPTION)
                .generate();

        var responseEncryptionJson = String.format("""
                        {
                            "alg": "%s",
                            "enc": "%s",
                            "jwk": %s
                        }
                        """, JWEAlgorithm.ECDH_ES.getName(), EncryptionMethod.A128GCM.getName(),
                encryptionKey.toPublicJWK().toJSONString());
        var credentialRequestString = getCredentialRequestStringV2(mock, holderKeys, applicationProperties, responseEncryptionJson);

        // Request encryption
        var requestEncryption = metadata.getRequestEncryption();
        assertThat(requestEncryption).isNotNull();
        assertThat(requestEncryption.getJwks()).isNotNull();
        assertTrue(requestEncryption.getZipValuesSupported().contains(CompressionAlgorithm.DEF.getName()));
        var jwks = assertDoesNotThrow(() -> JWKSet.parse(requestEncryption.getJwks()));
        var requestKey = jwks.getKeys().getFirst().toECKey();
        var requestEncryptor = assertDoesNotThrow(() -> new ECDHEncrypter(requestKey));
        var requestJweHeader = new JWEHeader.Builder(
                JWEAlgorithm.ECDH_ES,
                EncryptionMethod.parse(requestEncryption.getEncValuesSupported().getFirst()))
                .keyID(requestKey.getKeyID())
                .compressionAlgorithm(CompressionAlgorithm.DEF).build();
        var jweObject = new JWEObject(requestJweHeader, new Payload(credentialRequestString));
        assertDoesNotThrow(() -> jweObject.encrypt(requestEncryptor));
        var encryptedRequestMessage = assertDoesNotThrow(jweObject::serialize);
        var response = mock.perform(post("/oid4vci/api/credential")
                        .header("Authorization", String.format("BEARER %s", token))
                        .header("SWIYU-API-Version", "2")
                        .content(encryptedRequestMessage)
                        .contentType("application/jwt") // For encrypted credential request must be application/jwt
                )
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/jwt"))
                .andExpect(jsonPath("$").isNotEmpty())
                .andReturn();

        var jwe = JWEObject.parse(response.getResponse().getContentAsString());
        jwe.decrypt(new ECDHDecrypter(encryptionKey.toECPrivateKey()));
        var jweContent = jwe.getPayload().toString();
        JsonObject credentialResponse = JsonParser.parseString(jweContent).getAsJsonObject();
        JsonArray credentials = credentialResponse.get("credentials").getAsJsonArray();
        JsonObject credential = credentials.get(0).getAsJsonObject();
        var vc = credential.get("credential").getAsString();

        TestInfrastructureUtils.verifyVC(sdjwtProperties, vc, getUniversityCredentialSubjectData());
    }

    @Test
    void testSdJwtOffer_withMultipleProof_thenSuccess() throws Exception {

        var numberOfProofs = 3;

        List<ECKey> holderPrivateKeys = createHolderPrivateKeysV2(numberOfProofs);

        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");
        var credentialRequestString = getCredentialRequestStringV2(mock, holderPrivateKeys, applicationProperties);

        var response = requestCredentialV2(mock, (String) token, credentialRequestString)
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/json"))
                .andExpect(jsonPath("$.credentials").isNotEmpty())
                .andExpect(jsonPath("$.transaction_id").doesNotExist())
                .andExpect(jsonPath("$.interval").doesNotExist())
                .andReturn();

        var credentials = extractCredentialsV2(response);

        assertEquals(numberOfProofs, credentials.size());

        for (int j = 0; j < numberOfProofs; j++) {
            var credential = credentials.get(j).getAsJsonObject();
            var credentialString = credential.get("credential").getAsString();
            testHolderBindingV2(credentialString, holderPrivateKeys.get(j));
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 4})
    void testSdJwtOffer_invalidBatchSizes_thenBadRequest(int numberOfProofs) throws Exception {

        List<ECKey> holderPrivateKeys = createHolderPrivateKeysV2(numberOfProofs);

        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");
        var credentialRequestString = getCredentialRequestStringV2(mock, holderPrivateKeys, applicationProperties);

        requestCredentialV2(mock, (String) token, credentialRequestString)
                .andExpect(status().isBadRequest())
                .andReturn();
    }

    @Test
    void testSdJwtOffer_noBatchIssuanceAllowed_thenException() throws Exception {

        doReturn(null).when(issuerMetadata).getBatchCredentialIssuance();

        var numberOfProofs = 2;

        List<ECKey> holderPrivateKeys = createHolderPrivateKeysV2(numberOfProofs);

        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");
        var credentialRequestString = getCredentialRequestStringV2(mock, holderPrivateKeys, applicationProperties);

        requestCredentialV2(mock, (String) token, credentialRequestString)
                .andExpect(status().isBadRequest())
                .andReturn();
    }

    private CredentialOffer saveStatusListLinkedOffer(CredentialOffer offer, StatusList statusList, int index) {
        credentialManagement = credentialManagementRepository.save(CredentialManagement.builder()
                .id(UUID.randomUUID())
                .accessToken(UUID.randomUUID())
                .accessTokenExpirationTimestamp(Instant.now().plusSeconds(120).getEpochSecond())
                .renewalRequestCnt(0)
                .renewalResponseCnt(0)
                .build());

        offer.setCredentialManagement(credentialManagement);
        var storedOffer = credentialOfferRepository.save(offer);
        credentialOfferStatusRepository.save(linkStatusList(offer, statusList, index));

        credentialManagement.addCredentialOffer(storedOffer);
        credentialManagementRepository.save(credentialManagement);
        return storedOffer;
    }

    private StatusList saveStatusList(StatusList statusList) {
        return statusListRepository.save(statusList);
    }
}