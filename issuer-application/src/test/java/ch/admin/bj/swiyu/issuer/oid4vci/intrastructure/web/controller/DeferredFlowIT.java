/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.api.credentialoffer.CreateCredentialRequestDto;
import ch.admin.bj.swiyu.issuer.api.credentialoffer.CredentialOfferDto;
import ch.admin.bj.swiyu.issuer.api.credentialoffer.CredentialWithDeeplinkResponseDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.DeferredDataDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.AttackPotentialResistance;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofType;
import ch.admin.bj.swiyu.issuer.oid4vci.test.TestInfrastructureUtils;
import ch.admin.bj.swiyu.issuer.oid4vci.test.TestServiceUtils;
import ch.admin.bj.swiyu.issuer.service.DidTdwKeyResolver;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonParser;
import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionCallbackWithoutResult;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static ch.admin.bj.swiyu.issuer.oid4vci.test.CredentialOfferTestData.*;
import static ch.admin.bj.swiyu.issuer.oid4vci.test.TestInfrastructureUtils.requestCredential;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
@Transactional
class DeferredFlowIT {

    private static ECKey jwk;
    private final UUID deferredPreAuthCode = UUID.randomUUID();
    private final UUID notDeferredPreAuthCode = UUID.randomUUID();
    private final Instant validFrom = Instant.now();
    private final Instant validUntil = Instant.now().plus(30, ChronoUnit.DAYS);
    private final String deferredCredentialEndpoint = "/oid4vci/api/deferred_credential";
    private final ObjectMapper objectMapper = new ObjectMapper();
    @MockitoBean
    DidTdwKeyResolver didTdwKeyResolver;
    @Autowired
    private MockMvc mock;
    @Autowired
    private CredentialOfferRepository credentialOfferRepository;
    @Autowired
    private StatusListRepository statusListRepository;
    @Autowired
    private CredentialOfferStatusRepository credentialOfferStatusRepository;
    @Autowired
    private SdjwtProperties sdjwtProperties;
    @Autowired
    private ApplicationProperties applicationProperties;
    @Autowired
    private TransactionTemplate transactionTemplate;


    private Map<String, String> offerData;

    private static String getCredentialRequestString(String proof) {
        return String.format("{ \"format\": \"vc+sd-jwt\" , \"proof\": {\"proof_type\": \"jwt\", \"jwt\": \"%s\"}}", proof);
    }

    private static String getDeferredCredentialRequestString(String transactionId) {
        return String.format("{ \"transaction_id\": \"%s\"}", transactionId);
    }

    private static Map<String, Object> getCredentialMetadata(Boolean deferred) {
        return Map.of("vct#integrity", "sha256-SVHLfKfcZcBrw+d9EL/1EXxvGCdkQ7tMGvZmd0ysMck=", "deferred", deferred);
    }

    @BeforeEach
    void setUp() throws JOSEException {
        var statusList = saveStatusList(createStatusList());
        var deferredOffer = createTestOffer(deferredPreAuthCode, CredentialStatusType.OFFERED, "university_example_sd_jwt", validFrom, validUntil, getCredentialMetadata(true));
        saveStatusListLinkedOffer(deferredOffer, statusList);
        var notDeferredOffer = createTestOffer(notDeferredPreAuthCode, CredentialStatusType.OFFERED, "university_example_sd_jwt", validFrom, validUntil, getCredentialMetadata(false));
        saveStatusListLinkedOffer(notDeferredOffer, statusList);

        jwk = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("Test-Key")
                .issueTime(new Date())
                .generate();

        offerData = getTestOfferData();
    }

    @Test
    void testCompleteFlow_thenSuccess() throws Exception {

        var offerRequest = CreateCredentialRequestDto.builder()
                .metadataCredentialSupportedId(List.of("test"))
                .credentialSubjectData(Map.of())
                .credentialMetadata(getCredentialMetadata(true))
                .build();

        var offerRequestString = objectMapper.writeValueAsString(offerRequest);

        // create initial credential offer
        var response = mock.perform(post("/management/api/credentials")
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(offerRequestString))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.management_id").isNotEmpty())
                .andExpect(jsonPath("$.offer_deeplink").isNotEmpty())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
                .andReturn();

        var credentialWithDeeplinkResponseDto = objectMapper.readValue(response.getResponse().getContentAsString(), CredentialWithDeeplinkResponseDto.class);

        var credentialOffer = extractCredentialOfferFromResponse(credentialWithDeeplinkResponseDto);

        // get token
        var tokenResponse = mock.perform(post("/oid4vci/api/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
                        .param("pre-authorized_code", credentialOffer.getGrants().preAuthorizedCode().preAuthCode().toString()))
                .andExpect(status().isOk())
                .andReturn();

        var tokenDto = objectMapper.readValue(tokenResponse.getResponse().getContentAsString(), Map.class);

        String proof = TestServiceUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), (String) tokenDto.get("c_nonce"), ProofType.JWT.getClaimTyp(), false);

        var deferredCredentialResponse = requestCredential(mock, (String) tokenDto.get("access_token"), getCredentialRequestString(proof))
                .andExpect(status().isAccepted())
                .andReturn();

        DeferredDataDto deferredDataDto = objectMapper.readValue(deferredCredentialResponse.getResponse().getContentAsString(), DeferredDataDto.class);

        assertNotNull(deferredDataDto.transactionId());

        // check status from business issuer perspective
        mock.perform(get("/management/api/credentials/" + credentialWithDeeplinkResponseDto.getManagementId() + "/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("DEFERRED"))
                .andReturn();

        mock.perform(get("/management/api/credentials/" + credentialWithDeeplinkResponseDto.getManagementId()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("DEFERRED"))
                .andExpect(jsonPath("$.holder_jwks[0]").value(SignedJWT.parse(proof).getHeader().getJWK().toJSONString()))
                .andExpect(jsonPath("$.key_attestations").isEmpty())
                .andReturn();

        mock.perform(patch("/management/api/credentials/" + credentialWithDeeplinkResponseDto.getManagementId())
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(objectMapper.writeValueAsString(offerData)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").isNotEmpty())
                .andExpect(jsonPath("$.status").value("READY"))
                .andReturn();

        // check status from business issuer perspective
        mock.perform(get("/management/api/credentials/" + credentialWithDeeplinkResponseDto.getManagementId() + "/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("READY"))
                .andReturn();

        String deferredCredentialRequestString = getDeferredCredentialRequestString(deferredDataDto.transactionId().toString());

        var credentialResponse = mock.perform(post(deferredCredentialEndpoint)
                        .header("Authorization", String.format("BEARER %s", tokenDto.get("access_token")))
                        .contentType("application/json")
                        .content(deferredCredentialRequestString))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.credential").isNotEmpty())
                .andExpect(jsonPath("$.format").value("vc+sd-jwt"))
                .andReturn();

        var vc = JsonParser.parseString(credentialResponse.getResponse().getContentAsString()).getAsJsonObject().get("credential").getAsString();
        TestInfrastructureUtils.verifyVC(sdjwtProperties, vc, offerData);
    }

    @Test
    void testCompleteFlow_withKeyAttestation_thenSuccess() throws Exception {

        var offerRequest = CreateCredentialRequestDto.builder()
                .metadataCredentialSupportedId(List.of("test"))
                .credentialSubjectData(Map.of())
                .credentialMetadata(getCredentialMetadata(true))
                .build();

        var offerRequestString = objectMapper.writeValueAsString(offerRequest);

        // create initial credential offer
        var response = mock.perform(post("/management/api/credentials")
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(offerRequestString))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.management_id").isNotEmpty())
                .andExpect(jsonPath("$.offer_deeplink").isNotEmpty())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
                .andReturn();

        var credentialWithDeeplinkResponseDto = objectMapper.readValue(response.getResponse().getContentAsString(), CredentialWithDeeplinkResponseDto.class);

        var credentialOffer = extractCredentialOfferFromResponse(credentialWithDeeplinkResponseDto);

        Mockito.when(didTdwKeyResolver.resolveKey(Mockito.any())).thenReturn(jwk.toPublicJWK());

        var tokenResponse = mock.perform(post("/oid4vci/api/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
                        .param("pre-authorized_code", credentialOffer.getGrants().preAuthorizedCode().preAuthCode().toString()))
                .andExpect(status().isOk())
                .andReturn();

        var tokenDto = objectMapper.readValue(tokenResponse.getResponse().getContentAsString(), Map.class);

        String proof = TestServiceUtils.createAttestedHolderProof(
                jwk,
                applicationProperties.getTemplateReplacement().get("external-url"),
                (String) tokenDto.get("c_nonce"),
                ProofType.JWT.getClaimTyp(),
                false,
                AttackPotentialResistance.ISO_18045_HIGH,
                null);

        var deferredCredentialResponse = requestCredential(mock, (String) tokenDto.get("access_token"), String.format("{ \"format\": \"vc+sd-jwt\" , \"proof\": {\"proof_type\": \"jwt\", \"jwt\": \"%s\"}}", proof))
                .andExpect(status().isAccepted())
                .andReturn();

        DeferredDataDto deferredDataDto = objectMapper.readValue(deferredCredentialResponse.getResponse().getContentAsString(), DeferredDataDto.class);

        assertNotNull(deferredDataDto.transactionId());

        // check status from business issuer perspective
        mock.perform(get("/management/api/credentials/" + credentialWithDeeplinkResponseDto.getManagementId() + "/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("DEFERRED"))
                .andReturn();

        mock.perform(get("/management/api/credentials/" + credentialWithDeeplinkResponseDto.getManagementId()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("DEFERRED"))
                .andExpect(jsonPath("$.holder_jwks[0]").value(SignedJWT.parse(proof).getHeader().getJWK().toJSONString()))
                .andExpect(jsonPath("$.key_attestations").value(SignedJWT.parse(proof).getHeader().getCustomParam("key_attestation").toString()))
                .andReturn();

        mock.perform(patch("/management/api/credentials/" + credentialWithDeeplinkResponseDto.getManagementId())
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(objectMapper.writeValueAsString(offerData)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").isNotEmpty())
                .andExpect(jsonPath("$.status").value("READY"))
                .andReturn();

        // check status from business issuer perspective
        mock.perform(get("/management/api/credentials/" + credentialWithDeeplinkResponseDto.getManagementId() + "/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("READY"))
                .andReturn();

        String deferredCredentialRequestString = getDeferredCredentialRequestString(deferredDataDto.transactionId().toString());

        var credentialResponse = mock.perform(post(deferredCredentialEndpoint)
                        .header("Authorization", String.format("BEARER %s", tokenDto.get("access_token")))
                        .contentType("application/json")
                        .content(deferredCredentialRequestString))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.credential").isNotEmpty())
                .andExpect(jsonPath("$.format").value("vc+sd-jwt"))
                .andReturn();

        var vc = JsonParser.parseString(credentialResponse.getResponse().getContentAsString()).getAsJsonObject().get("credential").getAsString();
        TestInfrastructureUtils.verifyVC(sdjwtProperties, vc, offerData);
    }

    @Test
    void testBoundDeferredFlow_thenIssuancePendingException() throws Exception {

        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, deferredPreAuthCode.toString());
        String token = (String) tokenResponse.get("access_token");

        String proof = TestServiceUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), tokenResponse.get("c_nonce").toString(), ProofType.JWT.getClaimTyp(), false);
        String credentialRequestString = getCredentialRequestString(proof);

        var response = requestCredential(mock, token, credentialRequestString)
                .andExpect(status().isAccepted())
                .andReturn();

        // to get token now should end up in a bad request
        String transactionId = JsonPath.read(response.getResponse().getContentAsString(), "$.transaction_id");
        String deferredCredentialRequestString = getDeferredCredentialRequestString(transactionId);
        mock.perform(post(deferredCredentialEndpoint)
                        .header("Authorization", String.format("BEARER %s", token))
                        .contentType("application/json")
                        .content(deferredCredentialRequestString))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("ISSUANCE_PENDING"))
                .andReturn();
    }

    @Test
    void testBoundDeferredFlowWithInvalidTransactionId_thenInvalidCredentialRequestException() throws Exception {

        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, deferredPreAuthCode.toString());
        String token = (String) tokenResponse.get("access_token");

        String transactionId = "00000000-0000-0000-0000-000000000000";
        String deferredCredentialRequestString = getDeferredCredentialRequestString(transactionId);
        mock.perform(post(deferredCredentialEndpoint)
                        .header("Authorization", String.format("BEARER %s", token))
                        .contentType("application/json")
                        .content(deferredCredentialRequestString))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("INVALID_TRANSACTION_ID"))
                .andReturn();
    }

    @Test
    void testWrongBearer_thenInvalidCredentialRequestException() throws Exception {
        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, deferredPreAuthCode.toString());
        String token = (String) tokenResponse.get("access_token");
        String proof = TestServiceUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), tokenResponse.get("c_nonce").toString(), ProofType.JWT.getClaimTyp(), false);
        String credentialRequestString = getCredentialRequestString(proof);

        var response = requestCredential(mock, token, credentialRequestString)
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.transaction_id").isNotEmpty())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
                .andReturn();

        String transactionId = JsonPath.read(response.getResponse().getContentAsString(), "$.transaction_id");
        setCredentialToReady(token);

        String deferredCredentialRequestString = getDeferredCredentialRequestString(transactionId);

        mock.perform(post(deferredCredentialEndpoint)
                        .header("Authorization", String.format("BEARER %s", UUID.randomUUID()))
                        .contentType("application/json")
                        .content(deferredCredentialRequestString))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("INVALID_TOKEN"))
                .andExpect(jsonPath("$.error_description").value("Invalid accessToken"))
                .andReturn();
    }

    @Test
    void testWrongTransactionIdToken_thenInvalidCredentialRequestException() throws Exception {

        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, deferredPreAuthCode.toString());
        String token = (String) tokenResponse.get("access_token");
        String proof = TestServiceUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), tokenResponse.get("c_nonce").toString(), ProofType.JWT.getClaimTyp(), false);
        String credentialRequestString = getCredentialRequestString(proof);

        // wrong token
        var otherTokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, notDeferredPreAuthCode.toString());
        var otherToken = otherTokenResponse.get("access_token");

        var response = requestCredential(mock, token, credentialRequestString)
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.transaction_id").isNotEmpty())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
                .andReturn();

        String transactionId = JsonPath.read(response.getResponse().getContentAsString(), "$.transaction_id");
        setCredentialToReady(token);

        String deferredCredentialRequestString = getDeferredCredentialRequestString(transactionId);

        mock.perform(post(deferredCredentialEndpoint)
                        .header("Authorization", String.format("BEARER %s", otherToken))
                        .contentType("application/json")
                        .content(deferredCredentialRequestString))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("INVALID_TRANSACTION_ID"))
                .andExpect(jsonPath("$.error_description").value("Invalid transactional id"))
                .andReturn();
    }

    @Test
    void testBoundDeferredFlowWithAlreadyIssuedCredential_thenInvalidCredentialRequestException() throws Exception {

        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, deferredPreAuthCode.toString());
        String token = (String) tokenResponse.get("access_token");

        String proof = TestServiceUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), tokenResponse.get("c_nonce").toString(), ProofType.JWT.getClaimTyp(), false);
        String credentialRequestString = getCredentialRequestString(proof);

        var response = requestCredential(mock, token, credentialRequestString)
                .andExpect(status().isAccepted())
                .andReturn();

        String transactionId = JsonPath.read(response.getResponse().getContentAsString(), "$.transaction_id");

        // Mock issuer management interaction
        setCredentialToReady(token);

        String deferredCredentialRequestString = String.format("{ \"transaction_id\": \"%s\"}}", transactionId);

        var credentialResponse = getDeferredCallResultActions(token, deferredCredentialRequestString)
                .andExpect(status().isOk())
                .andReturn();

        var vc = JsonParser.parseString(credentialResponse.getResponse().getContentAsString()).getAsJsonObject().get("credential").getAsString();
        TestInfrastructureUtils.verifyVC(sdjwtProperties, vc, getUniversityCredentialSubjectData());

        getDeferredCallResultActions(token, deferredCredentialRequestString)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("INVALID_TRANSACTION_ID"))
                .andReturn();
    }

    private StatusList saveStatusList(StatusList statusList) {
        return statusListRepository.save(statusList);
    }

    private void saveStatusListLinkedOffer(CredentialOffer offer, StatusList statusList) {
        credentialOfferRepository.save(offer);
        credentialOfferStatusRepository.save(linkStatusList(offer, statusList));
        statusList.incrementNextFreeIndex();
    }

    private ResultActions getDeferredCallResultActions(Object token, String deferredCredentialRequestString) throws Exception {
        return mock.perform(post(deferredCredentialEndpoint)
                .header("Authorization", String.format("BEARER %s", token))
                .contentType("application/json")
                .content(deferredCredentialRequestString));
    }

    private void setCredentialToReady(String token) {
        transactionTemplate.execute(new TransactionCallbackWithoutResult() {
            @Override
            protected void doInTransactionWithoutResult(@NotNull TransactionStatus status) {
                var credentialOffer = credentialOfferRepository.findByAccessToken(UUID.fromString(token)).orElseThrow();
                credentialOffer.setCredentialStatus(CredentialStatusType.READY);
                credentialOfferRepository.save(credentialOffer);
            }
        });
    }

    private CredentialOfferDto extractCredentialOfferFromResponse(CredentialWithDeeplinkResponseDto dto) throws Exception {

        var decodedDeeplink = URLDecoder.decode(dto.getOfferDeeplink(), StandardCharsets.UTF_8);

        var credentialOfferString = decodedDeeplink.replace("swiyu://?credential_offer=", "");

        return objectMapper.readValue(credentialOfferString, CredentialOfferDto.class);
    }

    private Map<String, String> getTestOfferData() {
        Map<String, String> testOfferData = new HashMap<>();
        testOfferData.put("lastName", "lastName");
        testOfferData.put("firstName", "firstName");
        testOfferData.put("dateOfBirth", "2000-01-01");
        return testOfferData;
    }
}