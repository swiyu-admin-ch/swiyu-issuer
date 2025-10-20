package ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.CredentialStatusTypeDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.DeferredDataDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofType;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.oid4vci.test.TestInfrastructureUtils;
import ch.admin.bj.swiyu.issuer.oid4vci.test.TestServiceUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.UnsupportedEncodingException;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.*;
import java.util.stream.IntStream;

import static ch.admin.bj.swiyu.issuer.oid4vci.test.CredentialOfferTestData.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mockStatic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
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
    private final UUID validUnboundPreAuthCode = UUID.randomUUID();
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
    private CredentialOffer offer;
    private CredentialOffer unboundOffer;
    private StatusList statusList;
    @Autowired
    private IssuerMetadata issuerMetadata;

    private static String getDeferredCredentialRequestString(String transactionId) {
        return String.format("{ \"transaction_id\": \"%s\"}", transactionId);
    }

    @BeforeEach
    void setUp() throws JOSEException {
        statusList = saveStatusList(createStatusList());
        var deferredMetadata = new CredentialOfferMetadata(true, null, null, null);

        offer = createTestOffer(validPreAuthCode, CredentialStatusType.OFFERED, "university_example_sd_jwt",
                deferredMetadata);
        unboundOffer = createTestOffer(validUnboundPreAuthCode, CredentialStatusType.OFFERED,
                "unbound_example_sd_jwt", deferredMetadata);
        saveStatusListLinkedOffer(offer, statusList, 0);
        saveStatusListLinkedOffer(unboundOffer, statusList, 1);
        holderKeys = IntStream.range(0, issuerMetadata.getIssuanceBatchSize()).boxed().map(i -> assertDoesNotThrow(() -> new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("Test-Key-" + i)
                .issueTime(new Date())
                .generate())
        ).toList();
    }

    @Test
    void testDeferredOffer_withProof_thenSuccess() throws Exception {

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
        mock.perform(patch("/management/api/credentials/%s/status?credentialStatus=%s".formatted(offer.getId(),
                        CredentialStatusTypeDto.READY.name()))
                        .contentType("application/json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("READY"))
                .andReturn();

        DeferredDataDto deferredDataDto = objectMapper.readValue(
                deferredCredentialResponse.getResponse()
                        .getContentAsString(), DeferredDataDto.class);

        String deferredCredentialRequestString = getDeferredCredentialRequestString(
                deferredDataDto.transactionId()
                        .toString());

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
    void testDeferredOffer_withResponseEncryption_thenSuccess() throws Exception {

        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");

        ECKey ecJWK = new ECKeyGenerator(Curve.P_256)
                .keyID("transportEncKeyEC")
                .generate();

        var responseEncryptionJson = String.format("""
                        {
                            "alg": "%s",
                            "enc": "%s",
                            "jwk": %s
                        }
                        """, JWEAlgorithm.ECDH_ES.getName(), EncryptionMethod.A128GCM.getName(),
                ecJWK.toPublicJWK()
                        .toJSONString());

        // credential_response_encryption
        var credentialRequestString = getCredentialRequestString(tokenResponse.get("c_nonce").toString(),
                "university_example_sd_jwt", responseEncryptionJson);

        var deferredCredentialResponse = requestCredential(mock, (String) token, credentialRequestString)
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

        // check status from business issuer perspective
        mock.perform(patch("/management/api/credentials/%s/status?credentialStatus=%s".formatted(offer.getId(),
                        CredentialStatusTypeDto.READY.name()))
                        .contentType("application/json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("READY"))
                .andReturn();

        String deferredCredentialRequestString = getDeferredCredentialRequestString(
                deferredCredential.get("transaction_id")
                        .getAsString());

        var credentialsWrapperResponse = mock.perform(post("/oid4vci/api/deferred_credential")
                        .header("Authorization", String.format("BEARER %s", token))
                        .header("SWIYU-API-Version", "2")
                        .contentType("application/json")
                        .content(deferredCredentialRequestString))
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/jwt"))
                .andReturn();

        JsonObject credentialsWrapper = getEncryptedPayload(credentialsWrapperResponse, ecJWK);
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
        mock.perform(patch("/management/api/credentials/%s/status?credentialStatus=%s".formatted(offer.getId(),
                        CredentialStatusTypeDto.CANCELLED.name()))
                        .contentType("application/json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("CANCELLED"))
                .andReturn();

        DeferredDataDto deferredDataDto = objectMapper.readValue(
                deferredCredentialResponse.getResponse()
                        .getContentAsString(), DeferredDataDto.class);

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
                .andExpect(jsonPath("$.error").value("CREDENTIAL_REQUEST_DENIED"))
                .andExpect(jsonPath("$.error_description").value(
                        "The credential can not be issued anymore, the offer was either cancelled or expired"))

                .andReturn();
    }

    @Test
    void testDeferredOffer_withoutProof_thenSuccess() throws Exception {

        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validUnboundPreAuthCode.toString());
        var token = tokenResponse.get("access_token");
        var credentialRequestString = getCredentialRequestString(tokenResponse, "unbound_example_sd_jwt");

        var deferredCredentialResponse = requestCredential(mock, (String) token, credentialRequestString)
                .andExpect(status().isAccepted())
                .andReturn();

        // check status from business issuer perspective
        mock.perform(patch("/management/api/credentials/%s/status?credentialStatus=%s"
                        .formatted(unboundOffer.getId(), CredentialStatusTypeDto.READY.name())))
                .andExpect(status().isOk())
                .andReturn();

        DeferredDataDto deferredDataDto = objectMapper.readValue(
                deferredCredentialResponse.getResponse()
                        .getContentAsString(), DeferredDataDto.class);

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

        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validUnboundPreAuthCode.toString());
        var token = tokenResponse.get("access_token");
        var credentialRequestString = getCredentialRequestString(tokenResponse, "unbound_example_sd_jwt");

        Instant instant = Instant.now(Clock.fixed(Instant.parse("2025-01-01T00:00:00.00Z"), ZoneId.of("UTC")));

        try (MockedStatic<Instant> mockedStatic = mockStatic(Instant.class, Mockito.CALLS_REAL_METHODS)) {
            mockedStatic.when(Instant::now)
                    .thenReturn(instant);

            requestCredential(mock, (String) token, credentialRequestString)
                    .andExpect(status().isAccepted())
                    .andReturn();

            var result = credentialOfferRepository.findByIdForUpdate(unboundOffer.getId())
                    .orElseThrow();

            assertEquals(instant.plusSeconds(applicationProperties.getDeferredOfferValiditySeconds())
                    .getEpochSecond(), result.getOfferExpirationTimestamp());
        }
    }

    @Test
    void testDeferredOffer_withDynamicDeferredExpiration_thenSuccess() throws Exception {

        var expirationInSeconds = 1728000; // 20 days

        var offerWithDynamicExpiration = createTestOffer(UUID.randomUUID(), CredentialStatusType.IN_PROGRESS,
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
                    offerWithDynamicExpiration.getAccessToken()
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
        List<String> proofs = holderKeys.stream().map(holderKey -> assertDoesNotThrow(() -> TestServiceUtils.createHolderProof(holderKey,
                applicationProperties.getTemplateReplacement()
                        .get("external-url"), cNonce,
                ProofType.JWT.getClaimTyp(), false))).toList();


        var proofString = proofs.stream().reduce((a, b) -> a + "\", \"" + b).orElse("");
        if (encryption == null) {
            return String.format("{\"credential_configuration_id\": \"%s\", \"proofs\": {\"jwt\": [\"%s\"]}}",
                    configurationId, proofString);
        } else {
            return String.format("{\"credential_configuration_id\": \"%s\", \"credential_response_encryption\": %s, \"proofs\": {\"jwt\": [\"%s\"]}}", configurationId, encryption, proofString);
        }
    }


    private void saveStatusListLinkedOffer(CredentialOffer offer, StatusList statusList, int statusListIndex) {
        credentialOfferRepository.save(offer);
        credentialOfferStatusRepository.save(linkStatusList(offer, statusList, statusListIndex));
    }

    private StatusList saveStatusList(StatusList statusList) {
        return statusListRepository.save(statusList);
    }

    private ResultActions requestCredential(MockMvc mock, String token, String credentialRequestString)
            throws Exception {
        return mock.perform(post("/oid4vci/api/credential")
                .header("Authorization", String.format("BEARER %s", token))
                .header("SWIYU-API-Version", "2")
                .contentType("application/json")
                .content(credentialRequestString));
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
}