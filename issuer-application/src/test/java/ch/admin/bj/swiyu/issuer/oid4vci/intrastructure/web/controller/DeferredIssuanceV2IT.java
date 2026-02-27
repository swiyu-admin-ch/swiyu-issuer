package ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofType;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.dto.credentialoffer.CreateCredentialOfferRequestDto;
import ch.admin.bj.swiyu.issuer.dto.credentialoffer.CredentialOfferMetadataDto;
import ch.admin.bj.swiyu.issuer.dto.credentialofferstatus.UpdateCredentialStatusRequestTypeDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.DeferredDataDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.issuance_v2.CredentialEndpointResponseDtoV2;
import ch.admin.bj.swiyu.issuer.oid4vci.test.TestInfrastructureUtils;
import ch.admin.bj.swiyu.issuer.service.enc.JweService;
import ch.admin.bj.swiyu.issuer.service.test.TestServiceUtils;
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
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.UnsupportedEncodingException;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.IntStream;

import static ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller.IssuanceV2TestUtils.updateStatus;
import static ch.admin.bj.swiyu.issuer.oid4vci.test.CredentialOfferTestData.*;
import static ch.admin.bj.swiyu.issuer.oid4vci.test.TestInfrastructureUtils.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mockStatic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
@Transactional
class DeferredIssuanceV2IT {

    private final UUID validPreAuthCode = UUID.randomUUID();
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
    private ObjectMapper objectMapper;
    @Autowired
    private SdjwtProperties sdjwtProperties;
    private StatusList statusList;
    private UUID offerManagementId;
    @MockitoSpyBean
    private IssuerMetadata issuerMetadata;
    @Autowired
    private JweService encryptionService;
    @Autowired
    private CredentialManagementRepository credentialManagementRepository;

    private static String getDeferredCredentialRequestString(String transactionId) {
        return String.format("{ \"transaction_id\": \"%s\"}", transactionId);
    }

    private static String createResponseEncryptionJson(ECKey ecJWK) {
        return String.format("""
                        {
                            "alg": "%s",
                            "enc": "%s",
                            "jwk": %s
                        }
                        """, JWEAlgorithm.ECDH_ES.getName(), EncryptionMethod.A128GCM.getName(),
                ecJWK.toPublicJWK()
                        .toJSONString());
    }

    @BeforeEach
    void setUp() {
        statusList = saveStatusList(createStatusList());
        var deferredMetadata = new CredentialOfferMetadata(true, null, null, null);

        CredentialOffer offer = createTestOffer(validPreAuthCode, CredentialOfferStatusType.OFFERED,
                "university_example_sd_jwt",
                deferredMetadata);

        offerManagementId = saveStatusListLinkedOffer(offer, statusList, 0).getId();
        holderKeys = IntStream.range(0, issuerMetadata.getIssuanceBatchSize()).boxed()
                .map(i -> assertDoesNotThrow(() -> new ECKeyGenerator(Curve.P_256)
                        .keyUse(KeyUse.SIGNATURE)
                        .keyID("Test-Key-" + i)
                        .issueTime(new Date())
                        .generate()))
                .toList();
    }

    @Test
    void testDeferredOffer_withProof_thenSuccess() throws Exception {

        var offerRequest = CreateCredentialOfferRequestDto.builder()
                .metadataCredentialSupportedId(List.of("university_example_sd_jwt"))
                .credentialSubjectData(getUniversityCredentialSubjectData())
                .credentialMetadata(getCredentialMetadataDto())
                .build();

        // create initial credential offer
        var credentialWithDeeplinkResponseDto = createInitialCredentialWithDeeplinkResponse(mock, offerRequest);

        var credentialOffer = extractCredentialOfferDtoFromCredentialWithDeeplinkResponseDto(
                credentialWithDeeplinkResponseDto);

        var tokenResponse = fetchOAuthToken(mock,
                credentialOffer.getGrants().preAuthorizedCode().preAuthCode().toString());
        var token = tokenResponse.get("access_token");
        var credentialRequestString = getCredentialRequestString(tokenResponse, "university_example_sd_jwt");

        var deferredCredentialResponse = requestCredential(mock, (String) token, credentialRequestString)
                .andExpect(status().isAccepted())
                .andExpect(content().contentType("application/json"))
                .andExpect(jsonPath("$.credentials").doesNotExist())
                .andExpect(jsonPath("$.transaction_id").isNotEmpty())
                .andExpect(jsonPath("$.interval").isNotEmpty())
                .andReturn();

        var deferredResponseDto = objectMapper.readValue(
                deferredCredentialResponse.getResponse().getContentAsString(),
                CredentialEndpointResponseDtoV2.class);
        // Wallet starts polling
        String transactionId = deferredResponseDto.transactionId();
        String deferredCredentialRequestString = getDeferredCredentialRequestString(
                transactionId);
        mock.perform(post("/oid4vci/api/deferred_credential")
                        .header("Authorization", String.format("BEARER %s", token))
                        .contentType("application/json")
                        .header("SWIYU-API-Version", "2")
                        .content(deferredCredentialRequestString))
                .andExpect(status().isAccepted())
                .andExpect(content().contentType("application/json"))
                .andExpect(jsonPath("$.credentials").doesNotExist())
                .andExpect(jsonPath("$.transaction_id").isNotEmpty())
                .andExpect(jsonPath("$.transaction_id").value(transactionId))
                .andExpect(jsonPath("$.interval").isNotEmpty())
                .andReturn();

        // check status from business issuer perspective
        updateStatus(mock, credentialWithDeeplinkResponseDto.getManagementId().toString(),
                UpdateCredentialStatusRequestTypeDto.READY);

        mock.perform(post("/oid4vci/api/deferred_credential")
                        .header("Authorization", String.format("BEARER %s", token))
                        .contentType("application/json")
                        .header("SWIYU-API-Version", "2")
                        .content(deferredCredentialRequestString))
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/json"))
                .andExpect(jsonPath("$.credentials").isNotEmpty())
                .andExpect(jsonPath("$.transaction_id").doesNotExist())
                .andExpect(jsonPath("$.interval").doesNotExist())
                .andReturn();
    }

    @Test
    void testDeferredOffer_noBatching_withProof_thenSuccess() throws Exception {

        doReturn(null).when(issuerMetadata).getBatchCredentialIssuance();
        doReturn(false).when(issuerMetadata).isBatchIssuanceAllowed();

        holderKeys = List.of(new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("Test-Key")
                .issueTime(new Date())
                .generate());

        var offer = createCredentialOffer();
        var tokenResponse = fetchOAuthToken(mock, offer.getPreAuthorizedCode().toString());
        var token = tokenResponse.get("access_token");
        var credentialRequestString = getCredentialRequestString(tokenResponse, "university_example_sd_jwt");

        var deferredCredentialResponse = requestCredential(mock, (String) token, credentialRequestString)
                .andExpect(status().isAccepted())
                .andExpect(content().contentType("application/json"))
                .andExpect(jsonPath("$.credentials").doesNotExist())
                .andExpect(jsonPath("$.transaction_id").isNotEmpty())
                .andExpect(jsonPath("$.interval").isNotEmpty())
                .andReturn();

        var deferredResponseDto = objectMapper.readValue(
                deferredCredentialResponse.getResponse().getContentAsString(),
                CredentialEndpointResponseDtoV2.class);
        // Wallet starts polling
        String transactionId = deferredResponseDto.transactionId();
        String deferredCredentialRequestString = getDeferredCredentialRequestString(
                transactionId);
        mock.perform(post("/oid4vci/api/deferred_credential")
                        .header("Authorization", String.format("BEARER %s", token))
                        .contentType("application/json")
                        .header("SWIYU-API-Version", "2")
                        .content(deferredCredentialRequestString))
                .andExpect(status().isAccepted())
                .andExpect(content().contentType("application/json"))
                .andExpect(jsonPath("$.credentials").doesNotExist())
                .andExpect(jsonPath("$.transaction_id").isNotEmpty())
                .andExpect(jsonPath("$.transaction_id").value(transactionId))
                .andExpect(jsonPath("$.interval").isNotEmpty())
                .andReturn();

        updateStatus(mock, offer.getCredentialManagement().getId().toString(),
                UpdateCredentialStatusRequestTypeDto.READY);

        mock.perform(post("/oid4vci/api/deferred_credential")
                        .header("Authorization", String.format("BEARER %s", token))
                        .contentType("application/json")
                        .header("SWIYU-API-Version", "2")
                        .content(deferredCredentialRequestString))
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/json"))
                .andExpect(jsonPath("$.credentials").isNotEmpty())
                .andExpect(jsonPath("$.transaction_id").doesNotExist())
                .andExpect(jsonPath("$.interval").doesNotExist())
                .andReturn();
    }

    @Test
    void testDeferredOffer_notReady_thenAccepted() throws Exception {

        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");
        var credentialRequestString = getCredentialRequestString(tokenResponse, "university_example_sd_jwt");

        var deferredCredentialResponse = requestCredential(mock, (String) token, credentialRequestString)
                .andExpect(status().isAccepted())
                .andExpect(content().contentType("application/json"))
                .andExpect(jsonPath("$.credentials").doesNotExist())
                .andExpect(jsonPath("$.transaction_id").isNotEmpty())
                .andExpect(jsonPath("$.interval").isNotEmpty())
                .andReturn();

        DeferredDataDto deferredDataDto = objectMapper.readValue(
                deferredCredentialResponse.getResponse()
                        .getContentAsString(),
                DeferredDataDto.class);

        String deferredCredentialRequestString = getDeferredCredentialRequestString(
                deferredDataDto.transactionId()
                        .toString());

        mock.perform(post("/oid4vci/api/deferred_credential")
                        .header("Authorization", String.format("BEARER %s", token))
                        .contentType("application/json")
                        .header("SWIYU-API-Version", "2")
                        .content(deferredCredentialRequestString))
                .andExpect(status().isAccepted())
                .andExpect(content().contentType("application/json"))
                .andExpect(jsonPath("$.credentials").doesNotExist())
                .andExpect(jsonPath("$.transaction_id").isNotEmpty())
                .andExpect(jsonPath("$.interval").isNotEmpty())
                .andReturn();
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void testDeferredOffer_withResponseEncryption_thenSuccess(boolean rotateHolderEncryptionKey) throws Exception {

        var offer = createCredentialOffer();
        var tokenResponse = fetchOAuthToken(mock, offer.getPreAuthorizedCode().toString());
        var token = tokenResponse.get("access_token");

        ECKey ecJWK = new ECKeyGenerator(Curve.P_256)
                .keyID("transportEncKeyEC")
                .generate();

        var responseEncryptionJson = createResponseEncryptionJson(ecJWK);

        // credential_response_encryption
        var credentialRequestString = getCredentialRequestString(tokenResponse.get("c_nonce").toString(),
                "university_example_sd_jwt", responseEncryptionJson);

        var requestEncryptionSpec = encryptionService.issuerMetadataWithEncryptionOptions()
                .getRequestEncryption();
        var issuerEncryptionKey = JWKSet.parse(requestEncryptionSpec.getJwks()).getKeys().getFirst();
        var issuerEncrypter = new ECDHEncrypter(issuerEncryptionKey.toECKey());
        var jweHeader = new JWEHeader.Builder(JWEAlgorithm.ECDH_ES,
                EncryptionMethod.A128GCM).keyID(issuerEncryptionKey.getKeyID())
                .compressionAlgorithm(CompressionAlgorithm.DEF)
                .build();
        var encryptedRequest = new EncryptedJWT(jweHeader,
                JWTClaimsSet.parse(credentialRequestString));
        encryptedRequest.encrypt(issuerEncrypter);
        var deferredCredentialResponse = requestCredential(mock, (String) token, encryptedRequest.serialize(),
                true)
                .andExpect(status().isAccepted())
                .andExpect(content().contentType("application/jwt"))
                .andExpect(jsonPath("$").isNotEmpty())
                .andReturn();

        JsonObject deferredCredential = getEncryptedPayload(deferredCredentialResponse, ecJWK);

        assertFalse(deferredCredential.has("credentials"));
        assertTrue(deferredCredential.has("transaction_id"));
        assertTrue(deferredCredential.has("interval"));
        assertEquals(applicationProperties.getMinDeferredOfferIntervalSeconds(),
                deferredCredential.get("interval")
                        .getAsLong());

        var transactionId = deferredCredential.get("transaction_id").getAsString();
        // Deferred Credential Request
        JsonObject credentialsWrapper = deferredCredentialCall(
                token, transactionId, issuerEncrypter, jweHeader, status().isAccepted(), ecJWK,
                rotateHolderEncryptionKey);
        assertThat(credentialsWrapper.get("transaction_id").getAsString()).isEqualTo(transactionId)
                .as("When not yet ready, the transaction id should be returned");
        // update from business issuer perspective
        updateStatus(mock, offer.getCredentialManagement().getId().toString(),
                UpdateCredentialStatusRequestTypeDto.READY);

        // Deferred Credential Request
        credentialsWrapper = deferredCredentialCall(
                token, transactionId, issuerEncrypter, jweHeader, status().isOk(), ecJWK,
                rotateHolderEncryptionKey);

        JsonArray credentials = credentialsWrapper.get("credentials")
                .getAsJsonArray();
        JsonObject credential = credentials.get(0)
                .getAsJsonObject();
        var vc = credential.get("credential")
                .getAsString();

        assertTrue(credentialsWrapper.has("credentials"));
        assertFalse(credentialsWrapper.has("transaction_id"));
        assertFalse(credentialsWrapper.has("interval"));

        TestInfrastructureUtils.verifyVC(sdjwtProperties, vc, getUniversityCredentialSubjectData());
    }

    /**
     * Handles the process of requesting a deferred credential and decrypting the
     * response.
     * Optionally allows to rotate the encryption keys
     *
     * @param token                     The OAuth token used for authorization
     * @param transactionId             The transaction ID associated with the
     *                                  deferred credential request
     * @param issuerEncrypter           The ECDHEncrypter used for encrypting the
     *                                  request
     * @param jweHeader                 The JWE header used for the encrypted
     *                                  request
     * @param expectedStatus            The expected result status for the deferred
     *                                  credential request
     * @param ecJWK                     The ECKey used for response encryption
     * @param rotateHolderEncryptionKey A flag indicating whether to rotate the
     *                                  holder's encryption key
     * @return A JsonObject containing the encrypted payload of the credentials
     * wrapper response
     * @throws Exception if any I/O or parsing error occurs
     */
    private @NonNull JsonObject deferredCredentialCall(Object token, String transactionId,
                                                       ECDHEncrypter issuerEncrypter, JWEHeader jweHeader, ResultMatcher expectedStatus, ECKey ecJWK,
                                                       boolean rotateHolderEncryptionKey) throws Exception {
        var deferredCredentialRequestClaimBuilder = new JWTClaimsSet.Builder()
                .claim("transaction_id", transactionId);
        if (rotateHolderEncryptionKey) {
            ecJWK = new ECKeyGenerator(Curve.P_256)
                    .keyID("transportEncKeyECNew")
                    .generate();
            deferredCredentialRequestClaimBuilder.claim("credential_response_encryption",
                    JWTClaimsSet.parse(createResponseEncryptionJson(ecJWK)).getClaims());
        }
        String deferredCredentialRequestString = deferredCredentialRequestClaimBuilder.build().toString();
        var encryptedDeferredCredentialRequest = new EncryptedJWT(jweHeader,
                JWTClaimsSet.parse(deferredCredentialRequestString));
        encryptedDeferredCredentialRequest.encrypt(issuerEncrypter);

        var credentialsWrapperResponse = mock.perform(post("/oid4vci/api/deferred_credential")
                        .header("Authorization", String.format("BEARER %s", token))
                        .header("SWIYU-API-Version", "2")
                        .contentType("application/jwt")
                        .content(encryptedDeferredCredentialRequest.serialize()))
                .andExpect(expectedStatus)
                .andExpect(content().contentType("application/jwt"))
                .andReturn();
        return getEncryptedPayload(credentialsWrapperResponse, ecJWK);
    }

    @Test
    void testDeferredOffer_alreadyCancelled_thenSuccess() throws Exception {

        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");
        var credentialRequestString = getCredentialRequestString(tokenResponse, "university_example_sd_jwt");

        var deferredCredentialResponse = requestCredential(mock, (String) token, credentialRequestString)
                .andExpect(status().isAccepted())
                .andExpect(content().contentType("application/json"))
                .andExpect(jsonPath("$.credentials").doesNotExist())
                .andExpect(jsonPath("$.transaction_id").isNotEmpty())
                .andExpect(jsonPath("$.interval").isNotEmpty())
                .andReturn();

        // check status from business issuer perspective
        updateStatus(mock, offerManagementId.toString(), UpdateCredentialStatusRequestTypeDto.CANCELLED);

        DeferredDataDto deferredDataDto = objectMapper.readValue(
                deferredCredentialResponse.getResponse()
                        .getContentAsString(),
                DeferredDataDto.class);

        String deferredCredentialRequestString = getDeferredCredentialRequestString(
                deferredDataDto.transactionId()
                        .toString());

        mock.perform(post("/oid4vci/api/deferred_credential")
                        .header("Authorization", String.format("BEARER %s", token))
                        .contentType("application/json")
                        .header("SWIYU-API-Version", "2")
                        .content(deferredCredentialRequestString))
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType("application/json"))
                .andExpect(jsonPath("$.error_description").isNotEmpty())

                .andReturn();
    }

    @Test
    void testDeferredOffer_withoutProof_thenSuccess() throws Exception {

        var offer = createUnboundCredentialOffer();
        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock,
                offer.getPreAuthorizedCode().toString());
        var token = tokenResponse.get("access_token");
        var credentialRequestString = getCredentialRequestString(tokenResponse, "unbound_example_sd_jwt");

        var deferredCredentialResponse = requestCredential(mock, (String) token, credentialRequestString)
                .andExpect(status().isAccepted())
                .andReturn();

        // check status from business issuer perspective
        updateStatus(mock, offer.getCredentialManagement().getId().toString(),
                UpdateCredentialStatusRequestTypeDto.READY);

        DeferredDataDto deferredDataDto = objectMapper.readValue(
                deferredCredentialResponse.getResponse()
                        .getContentAsString(),
                DeferredDataDto.class);

        String deferredCredentialRequestString = getDeferredCredentialRequestString(
                deferredDataDto.transactionId()
                        .toString());

        mock.perform(post("/oid4vci/api/deferred_credential")
                        .header("Authorization", String.format("BEARER %s", token))
                        .header("SWIYU-API-Version", "2")
                        .contentType("application/json")
                        .content(deferredCredentialRequestString))
                .andExpect(status().isOk());
    }

    @Test
    void testDeferredOffer_noBatching_withoutProof_thenSuccess() throws Exception {

        doReturn(null).when(issuerMetadata).getBatchCredentialIssuance();
        doReturn(false).when(issuerMetadata).isBatchIssuanceAllowed();

        var offer = createUnboundCredentialOffer();
        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock,
                offer.getPreAuthorizedCode().toString());
        var token = tokenResponse.get("access_token");
        var credentialRequestString = getCredentialRequestString(tokenResponse, "unbound_example_sd_jwt");

        var deferredCredentialResponse = requestCredential(mock, (String) token, credentialRequestString)
                .andExpect(status().isAccepted())
                .andReturn();

        // check status from business issuer perspective
        updateStatus(mock, offer.getCredentialManagement().getId().toString(),
                UpdateCredentialStatusRequestTypeDto.READY);

        DeferredDataDto deferredDataDto = objectMapper.readValue(
                deferredCredentialResponse.getResponse()
                        .getContentAsString(),
                DeferredDataDto.class);

        String deferredCredentialRequestString = getDeferredCredentialRequestString(
                deferredDataDto.transactionId()
                        .toString());

        mock.perform(post("/oid4vci/api/deferred_credential")
                        .header("Authorization", String.format("BEARER %s", token))
                        .header("SWIYU-API-Version", "2")
                        .contentType("application/json")
                        .content(deferredCredentialRequestString))
                .andExpect(status().isOk());
    }

    @Test
    void testDeferredOffer_withDefaultDeferredExpiration_thenSuccess() throws Exception {

        var offer = createUnboundCredentialOffer();
        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock,
                offer.getPreAuthorizedCode().toString());
        var token = tokenResponse.get("access_token");
        var credentialRequestString = getCredentialRequestString(tokenResponse, "unbound_example_sd_jwt");

        Instant instant = Instant.now(Clock.fixed(Instant.parse("2025-01-01T00:00:00.00Z"), ZoneId.of("UTC")));

        try (MockedStatic<Instant> mockedStatic = mockStatic(Instant.class, Mockito.CALLS_REAL_METHODS)) {
            mockedStatic.when(Instant::now)
                    .thenReturn(instant);

            requestCredential(mock, (String) token, credentialRequestString)
                    .andExpect(status().isAccepted())
                    .andReturn();

            var result = credentialOfferRepository.findByIdForUpdate(offer.getId())
                    .orElseThrow();

            assertEquals(instant.plusSeconds(applicationProperties.getDeferredOfferValiditySeconds())
                    .getEpochSecond(), result.getOfferExpirationTimestamp());
        }
    }

    @Test
    void testDeferredOffer_withDynamicDeferredExpiration_thenSuccess() throws Exception {

        var expirationInSeconds = 1728000; // 20 days

        var offerWithDynamicExpiration = createTestOffer(UUID.randomUUID(),
                CredentialOfferStatusType.IN_PROGRESS,
                "university_example_sd_jwt", new CredentialOfferMetadata(true, null, null, null),
                expirationInSeconds);
        saveStatusListLinkedOffer(offerWithDynamicExpiration, statusList, 3);

        Instant instant = Instant.now(Clock.fixed(Instant.parse("2025-01-01T00:00:00.00Z"), ZoneId.of("UTC")));

        try (MockedStatic<Instant> mockedStatic = mockStatic(Instant.class, Mockito.CALLS_REAL_METHODS)) {
            mockedStatic.when(Instant::now)
                    .thenReturn(instant);

            var credentialRequestString = getCredentialRequestString(
                    offerWithDynamicExpiration.getNonce()
                            .toString(),
                    offerWithDynamicExpiration.getMetadataCredentialSupportedId()
                            .getFirst());

            requestCredential(mock,
                    offerWithDynamicExpiration.getCredentialManagement().getAccessToken()
                            .toString(),
                    credentialRequestString)
                    .andExpect(status().isAccepted())
                    .andReturn();

            var result = credentialOfferRepository.findByIdForUpdate(offerWithDynamicExpiration.getId())
                    .orElseThrow();

            assertEquals(instant.plusSeconds(expirationInSeconds)
                            .getEpochSecond(),
                    result.getOfferExpirationTimestamp());
        }
    }

    private String getCredentialRequestString(Map<String, Object> tokenResponse, String configurationId) {
        return getCredentialRequestString(tokenResponse.get("c_nonce")
                .toString(), configurationId);
    }

    private String getCredentialRequestString(String cNonce, String configurationId) {
        return getCredentialRequestString(cNonce, configurationId, null);
    }

    private String getCredentialRequestString(String cNonce, String configurationId, String encryption) {
        List<String> proofs = holderKeys.stream()
                .map(holderKey -> assertDoesNotThrow(() -> TestServiceUtils.createHolderProof(holderKey,
                        applicationProperties.getTemplateReplacement()
                                .get("external-url"),
                        cNonce,
                        ProofType.JWT.getClaimTyp(), false)))
                .toList();

        var proofString = proofs.stream().reduce((a, b) -> a + "\", \"" + b).orElse("");
        if (encryption == null) {
            return String.format(
                    "{\"credential_configuration_id\": \"%s\", \"proofs\": {\"jwt\": [\"%s\"]}}",
                    configurationId, proofString);
        } else {
            return String.format(
                    "{\"credential_configuration_id\": \"%s\", \"credential_response_encryption\": %s, \"proofs\": {\"jwt\": [\"%s\"]}}",
                    configurationId, encryption, proofString);
        }
    }

    private CredentialManagement saveStatusListLinkedOffer(CredentialOffer offer, StatusList statusList,
                                                           int index) {
        var credentialManagement = credentialManagementRepository.save(CredentialManagement.builder()
                .id(UUID.randomUUID())
                .accessToken(UUID.randomUUID())
                .credentialManagementStatus(CredentialStatusManagementType.INIT)
                .accessTokenExpirationTimestamp(Instant.now().plusSeconds(120).getEpochSecond())
                .renewalRequestCnt(0)
                .renewalResponseCnt(0)
                .build());

        offer.setCredentialManagement(credentialManagement);
        var storedOffer = credentialOfferRepository.save(offer);
        credentialOfferStatusRepository.save(linkStatusList(offer, statusList, index));

        credentialManagement.addCredentialOffer(storedOffer);
        credentialManagementRepository.save(credentialManagement);
        return credentialManagementRepository.save(credentialManagement);
    }

    private StatusList saveStatusList(StatusList statusList) {
        return statusListRepository.save(statusList);
    }

    private ResultActions requestCredential(MockMvc mock, String token, String credentialRequestString)
            throws Exception {
        return requestCredential(mock, token, credentialRequestString, false);
    }

    private ResultActions requestCredential(MockMvc mock, String token, String credentialRequestString,
                                            boolean encrypted)
            throws Exception {
        var requestBuilder = post("/oid4vci/api/credential")
                .header("Authorization", String.format("BEARER %s", token))
                .header("SWIYU-API-Version", "2")
                .contentType("application/json")
                .content(credentialRequestString);
        if (encrypted) {
            requestBuilder.contentType("application/jwt");
        } else {
            requestBuilder.contentType("application/json");
        }
        return mock.perform(requestBuilder);
    }

    private JsonObject getEncryptedPayload(MvcResult deferredCredentialResponse, ECKey ecJWK)
            throws ParseException, UnsupportedEncodingException, JOSEException {
        var jwe = JWEObject.parse(deferredCredentialResponse.getResponse()
                .getContentAsString());
        jwe.decrypt(new ECDHDecrypter(ecJWK.toECPrivateKey()));
        var jweContent = jwe.getPayload()
                .toString();
        return JsonParser.parseString(jweContent)
                .getAsJsonObject();
    }

    private CredentialOfferMetadataDto getCredentialMetadataDto() {
        return new CredentialOfferMetadataDto(true, "sha256-SVHLfKfcZcBrw+d9EL/1EXxvGCdkQ7tMGvZmd0ysMck=", null,
                null);
    }

    private CredentialOffer createUnboundCredentialOffer() throws Exception {
        var offerMetadata = new CredentialOfferMetadataDto(true,
                "sha256-SVHLfKfcZcBrw+d9EL/1EXxvGCdkQ7tMGvZmd0ysMck=", null, null);
        var offerRequest = CreateCredentialOfferRequestDto.builder()
                .metadataCredentialSupportedId(List.of("unbound_example_sd_jwt"))
                .credentialSubjectData(Map.of("animal", "animal"))
                .credentialMetadata(offerMetadata)
                .statusLists(List.of(statusList.getUri()))
                .build();

        var offer = createInitialCredentialWithDeeplinkResponse(mock, offerRequest);

        return credentialOfferRepository.findById(offer.getOfferId()).orElseThrow();
    }

    private CredentialOffer createCredentialOffer() throws Exception {

        var offerRequest = CreateCredentialOfferRequestDto.builder()
                .metadataCredentialSupportedId(List.of("university_example_sd_jwt"))
                .credentialSubjectData(getUniversityCredentialSubjectData())
                .credentialMetadata(getCredentialMetadataDto())
                .statusLists(List.of(statusList.getUri()))
                .build();

        var offer = createInitialCredentialWithDeeplinkResponse(mock, offerRequest);

        return credentialOfferRepository.findById(offer.getOfferId()).orElseThrow();
    }
}