package ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.AttackPotentialResistance;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofType;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.BatchCredentialIssuance;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.dto.credentialoffer.CreateCredentialOfferRequestDto;
import ch.admin.bj.swiyu.issuer.dto.credentialoffer.CredentialOfferMetadataDto;
import ch.admin.bj.swiyu.issuer.dto.credentialoffer.CredentialWithDeeplinkResponseDto;
import ch.admin.bj.swiyu.issuer.dto.credentialofferstatus.UpdateCredentialStatusRequestTypeDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.DeferredDataDto;
import ch.admin.bj.swiyu.issuer.oid4vci.test.TestInfrastructureUtils;
import ch.admin.bj.swiyu.issuer.service.did.DidKeyResolverFacade;
import ch.admin.bj.swiyu.issuer.service.test.TestServiceUtils;
import ch.admin.bj.swiyu.issuer.service.webhook.AsyncCredentialEventHandler;
import ch.admin.bj.swiyu.issuer.service.webhook.DeferredEvent;
import ch.admin.bj.swiyu.issuer.service.webhook.OfferStateChangeEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonParser;
import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.*;

import static ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller.IssuanceV2TestUtils.updateStatus;
import static ch.admin.bj.swiyu.issuer.oid4vci.test.CredentialOfferTestData.*;
import static ch.admin.bj.swiyu.issuer.oid4vci.test.TestInfrastructureUtils.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
@Transactional
class DeferredFlowIT {

    private static ECKey jwk;
    private final String deferredCredentialEndpoint = "/oid4vci/api/deferred_credential";
    private final ObjectMapper objectMapper = new ObjectMapper();
    @MockitoBean
    DidKeyResolverFacade didKeyResolver;
    @MockitoBean
    AsyncCredentialEventHandler testEventListener;
    @MockitoSpyBean
    private IssuerMetadata issuerMetadata;
    @Autowired
    private MockMvc mock;
    @Autowired
    private CredentialOfferRepository credentialOfferRepository;
    @Autowired
    private CredentialManagementRepository credentialManagementRepository;
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
    private StatusList statusList;

    @BeforeEach
    void setUp() throws JOSEException {
        statusList = saveStatusList(createStatusList());

        jwk = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("Test-Key")
                .issueTime(new Date())
                .generate();
    }

    @Test
    void testCompleteFlow_thenSuccess() throws Exception {

        var credentialWithDeeplinkResponseDto = getCredentialWithDeeplinkResponseDto();

        var credentialOffer = extractCredentialOfferDtoFromCredentialWithDeeplinkResponseDto(
                credentialWithDeeplinkResponseDto);

        var tokenDto = fetchOAuthToken(mock,
                credentialOffer.getGrants().preAuthorizedCode().preAuthCode().toString());

        String token = (String) tokenDto.get("access_token");

        verify(testEventListener, Mockito.times(1))
                .handleOfferStateChangeEvent(any(OfferStateChangeEvent.class));
        var nonce = requestNonce(mock);

        String proof = TestServiceUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), nonce, ProofType.JWT.getClaimTyp(), false);

        var deferredCredentialResponse = requestCredential(mock, token, getCredentialRequestString(proof))
                .andExpect(status().isAccepted())
                .andReturn();
        verify(testEventListener, Mockito.times(1)).handleDeferredEvent(any(DeferredEvent.class));

        DeferredDataDto deferredDataDto = objectMapper.readValue(
                deferredCredentialResponse.getResponse().getContentAsString(), DeferredDataDto.class);

        assertNotNull(deferredDataDto.transactionId());

        // check status from business issuer perspective
        mock.perform(get("/management/api/credentials/" + credentialWithDeeplinkResponseDto.getManagementId()
                        + "/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("DEFERRED"))
                .andReturn();

        mock.perform(get("/management/api/credentials/" + credentialWithDeeplinkResponseDto.getManagementId()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("DEFERRED"))
                .andExpect(jsonPath("$.credential_offers[0].holder_jwks[0]")
                        .value(SignedJWT.parse(proof).getHeader().getJWK().toJSONString()))
                .andExpect(jsonPath("$.credential_offers[0].key_attestations").doesNotExist())
                .andReturn();

        updateStatus(mock, credentialWithDeeplinkResponseDto.getManagementId().toString(), UpdateCredentialStatusRequestTypeDto.READY);

        // check status from business issuer perspective
        mock.perform(get("/management/api/credentials/" + credentialWithDeeplinkResponseDto.getManagementId()
                        + "/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("READY"))
                .andReturn();

        String deferredCredentialRequestString = getDeferredCredentialRequestString(
                deferredDataDto.transactionId().toString());

        var credentialResponse = mock.perform(post(deferredCredentialEndpoint)
                        .header("Authorization", String.format("BEARER %s", tokenDto.get("access_token")))
                        .contentType("application/json")
                        .content(deferredCredentialRequestString))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.credential").isNotEmpty())
                .andExpect(jsonPath("$.format").value("vc+sd-jwt"))
                .andReturn();
        // -> Claming_in_Progress -> Deferred -> Ready -> Issued
        verify(testEventListener, Mockito.times(4))
                .handleOfferStateChangeEvent(any(OfferStateChangeEvent.class));

        var vc = JsonParser.parseString(credentialResponse.getResponse().getContentAsString()).getAsJsonObject()
                .get("credential").getAsString();
        TestInfrastructureUtils.verifyVC(sdjwtProperties, vc, getUniversityCredentialSubjectData());
    }

    @Test
    void testCompleteFlow_batched_thenSuccess() throws Exception {

        doReturn(new BatchCredentialIssuance(10)).when(issuerMetadata).getBatchCredentialIssuance();
        doReturn(true).when(issuerMetadata).isBatchIssuanceAllowed();

        var offerRequest = CreateCredentialOfferRequestDto.builder()
                .metadataCredentialSupportedId(List.of("test"))
                .credentialSubjectData(Map.of("lastName", "lastName"))
                .credentialMetadata(getCredentialMetadataDto())
                .build();

        // create initial credential offer
        var credentialWithDeeplinkResponseDto = createInitialCredentialWithDeeplinkResponse(mock, offerRequest);

        var credentialOffer = extractCredentialOfferDtoFromCredentialWithDeeplinkResponseDto(
                credentialWithDeeplinkResponseDto);
        var nonce = requestNonce(mock);
        var tokenDto = fetchOAuthToken(mock,
                credentialOffer.getGrants().preAuthorizedCode().preAuthCode().toString());

        String proof = TestServiceUtils.createHolderProof(jwk,
                applicationProperties.getTemplateReplacement().get("external-url"),
                nonce, ProofType.JWT.getClaimTyp(), false);

        var deferredCredentialResponse = requestCredential(mock, (String) tokenDto.get("access_token"),
                getCredentialRequestString(proof))
                .andExpect(status().isAccepted())
                .andReturn();
        verify(testEventListener, Mockito.times(1)).handleDeferredEvent(any(DeferredEvent.class));

        DeferredDataDto deferredDataDto = objectMapper.readValue(
                deferredCredentialResponse.getResponse().getContentAsString(), DeferredDataDto.class);

        String deferredCredentialRequestString = getDeferredCredentialRequestString(
                deferredDataDto.transactionId().toString());

        updateStatus(mock, credentialWithDeeplinkResponseDto.getManagementId().toString(), UpdateCredentialStatusRequestTypeDto.READY);

        mock.perform(post(deferredCredentialEndpoint)
                        .header("Authorization", String.format("BEARER %s", tokenDto.get("access_token")))
                        .contentType("application/json")
                        .content(deferredCredentialRequestString))
                .andExpect(status().isOk())
                .andReturn();
    }

    @Test
    void testCompleteFlow_notBatched_thenSuccess() throws Exception {

        doReturn(null).when(issuerMetadata).getBatchCredentialIssuance();
        doReturn(false).when(issuerMetadata).isBatchIssuanceAllowed();

        var offerRequest = CreateCredentialOfferRequestDto.builder()
                .metadataCredentialSupportedId(List.of("test"))
                .credentialSubjectData(Map.of("lastName", "lastName"))
                .credentialMetadata(getCredentialMetadataDto())
                .build();

        // create initial credential offer
        var credentialWithDeeplinkResponseDto = createInitialCredentialWithDeeplinkResponse(mock, offerRequest);

        var credentialOffer = extractCredentialOfferDtoFromCredentialWithDeeplinkResponseDto(
                credentialWithDeeplinkResponseDto);

        var nonce = requestNonce(mock);
        var tokenDto = fetchOAuthToken(mock,
                credentialOffer.getGrants().preAuthorizedCode().preAuthCode().toString());

        String proof = TestServiceUtils.createHolderProof(jwk,
                applicationProperties.getTemplateReplacement().get("external-url"),
                nonce, ProofType.JWT.getClaimTyp(), false);

        var deferredCredentialResponse = requestCredential(mock, (String) tokenDto.get("access_token"),
                getCredentialRequestString(proof))
                .andExpect(status().isAccepted())
                .andReturn();
        verify(testEventListener, Mockito.times(1)).handleDeferredEvent(any(DeferredEvent.class));

        DeferredDataDto deferredDataDto = objectMapper.readValue(
                deferredCredentialResponse.getResponse().getContentAsString(), DeferredDataDto.class);

        String deferredCredentialRequestString = getDeferredCredentialRequestString(
                deferredDataDto.transactionId().toString());

        updateStatus(mock, credentialWithDeeplinkResponseDto.getManagementId().toString(), UpdateCredentialStatusRequestTypeDto.READY);

        mock.perform(post(deferredCredentialEndpoint)
                        .header("Authorization", String.format("BEARER %s", tokenDto.get("access_token")))
                        .contentType("application/json")
                        .content(deferredCredentialRequestString))
                .andExpect(status().isOk())
                .andReturn();
    }

    @Test
    void testCompleteFlow_withKeyAttestation_thenSuccess() throws Exception {

        var credentialWithDeeplinkResponseDto = getCredentialWithDeeplinkResponseDto();

        var credentialOffer = extractCredentialOfferDtoFromCredentialWithDeeplinkResponseDto(
                credentialWithDeeplinkResponseDto);

        Mockito.when(didKeyResolver.resolveKey(Mockito.any())).thenReturn(jwk.toPublicJWK());

        var tokenResponse = mock.perform(post("/oid4vci/api/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
                        .param("pre-authorized_code",
                                credentialOffer.getGrants().preAuthorizedCode().preAuthCode()
                                        .toString()))
                .andExpect(status().isOk())
                .andReturn();

        var tokenDto = objectMapper.readValue(tokenResponse.getResponse().getContentAsString(), Map.class);

        var nonce = requestNonce(mock);

        String proof = TestServiceUtils.createAttestedHolderProof(
                jwk,
                applicationProperties.getTemplateReplacement().get("external-url"),
                nonce,
                ProofType.JWT.getClaimTyp(),
                false,
                AttackPotentialResistance.ISO_18045_HIGH,
                null);

        var deferredCredentialResponse = requestCredential(mock, (String) tokenDto.get("access_token"), String
                .format("{ \"format\": \"vc+sd-jwt\" , \"proof\": {\"proof_type\": \"jwt\", \"jwt\": \"%s\"}}",
                        proof))
                .andExpect(status().isAccepted())
                .andReturn();

        DeferredDataDto deferredDataDto = objectMapper.readValue(
                deferredCredentialResponse.getResponse().getContentAsString(), DeferredDataDto.class);

        assertNotNull(deferredDataDto.transactionId());

        // check status from business issuer perspective
        mock.perform(get("/management/api/credentials/" + credentialWithDeeplinkResponseDto.getManagementId()
                        + "/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("DEFERRED"))
                .andReturn();

        mock.perform(get("/management/api/credentials/" + credentialWithDeeplinkResponseDto.getManagementId()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("DEFERRED"))
                .andExpect(jsonPath("$.credential_offers[0].holder_jwks[0]")
                        .value(SignedJWT.parse(proof).getHeader().getJWK().toJSONString()))
                .andExpect(jsonPath("$.credential_offers[0].key_attestations").value(SignedJWT
                        .parse(proof).getHeader().getCustomParam("key_attestation").toString()))
                .andReturn();

        updateStatus(mock, credentialWithDeeplinkResponseDto.getManagementId().toString(), UpdateCredentialStatusRequestTypeDto.READY);

        // check status from business issuer perspective
        mock.perform(get("/management/api/credentials/" + credentialWithDeeplinkResponseDto.getManagementId()
                        + "/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("READY"))
                .andReturn();

        String deferredCredentialRequestString = getDeferredCredentialRequestString(
                deferredDataDto.transactionId().toString());

        var credentialResponse = mock.perform(post(deferredCredentialEndpoint)
                        .header("Authorization", String.format("BEARER %s", tokenDto.get("access_token")))
                        .contentType("application/json")
                        .content(deferredCredentialRequestString))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.credential").isNotEmpty())
                .andExpect(jsonPath("$.format").value("vc+sd-jwt"))
                .andReturn();

        var vc = JsonParser.parseString(credentialResponse.getResponse().getContentAsString()).getAsJsonObject()
                .get("credential").getAsString();
        TestInfrastructureUtils.verifyVC(sdjwtProperties, vc, getUniversityCredentialSubjectData());
    }

    @Test
    void testOfferCreation_withNoSubjectData() throws Exception {

        var offerRequest = CreateCredentialOfferRequestDto.builder()
                .metadataCredentialSupportedId(List.of("test"))
                .credentialMetadata(getCredentialMetadataDto())
                .build();

        var offerRequestString = objectMapper.writeValueAsString(offerRequest);

        // create initial credential offer
        mock.perform(post("/management/api/credentials")
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(offerRequestString))
                .andExpect(status().is4xxClientError())
                .andExpect(jsonPath("$.error_description").value("Unprocessable Entity"))
                .andExpect(jsonPath("$.detail")
                        .value("credentialSubjectData: 'credential_subject_data' must be set"))
                .andReturn();
    }

    @Test
    void testOfferCreation_withUnexpectedClaim() throws Exception {

        var extendedOfferData = new HashMap<String, Object>(getUniversityCredentialSubjectData());
        extendedOfferData.put("unexpectedClaim", "unexpectedValue");

        var offerRequest = CreateCredentialOfferRequestDto.builder()
                .metadataCredentialSupportedId(List.of("university_example_sd_jwt"))
                .credentialMetadata(getCredentialMetadataDto())
                .credentialSubjectData(extendedOfferData)
                .build();

        var offerRequestString = objectMapper.writeValueAsString(offerRequest);

        // create initial credential offer
        mock.perform(post("/management/api/credentials")
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(offerRequestString))
                .andExpect(status().is4xxClientError())
                .andExpect(jsonPath("$.detail")
                        .value("Unexpected credential claims found! unexpectedClaim"))
                .andReturn();
    }

    @Test
    void testOfferCreation_withMissingMandatoryClaim() throws Exception {

        var extendedOfferData = new HashMap<String, Object>(getUniversityCredentialSubjectData());
        extendedOfferData.remove("lastName"); // removing required claim

        var offerRequest = CreateCredentialOfferRequestDto.builder()
                .metadataCredentialSupportedId(List.of("test"))
                .credentialMetadata(getCredentialMetadataDto())
                .credentialSubjectData(extendedOfferData)
                .build();

        var offerRequestString = objectMapper.writeValueAsString(offerRequest);

        // create initial credential offer
        mock.perform(post("/management/api/credentials")
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content(offerRequestString))
                .andExpect(status().is4xxClientError())
                .andExpect(jsonPath("$.detail")
                        .value("Mandatory credential claims are missing! lastName"))
                .andReturn();
    }

    // only for V1, we return 400 when Issuance pending!
    @Test
    void testBoundDeferredFlow_thenIssuancePendingException() throws Exception {

        var offer = getCredentialWithDeeplinkResponseDto();
        var credentialOffer = extractCredentialOfferDtoFromCredentialWithDeeplinkResponseDto(
                offer);
        var nonce = requestNonce(mock);
        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, credentialOffer.getGrants().preAuthorizedCode().preAuthCode().toString());
        String token = (String) tokenResponse.get("access_token");

        String proof = TestServiceUtils.createHolderProof(jwk,
                applicationProperties.getTemplateReplacement().get("external-url"),
                nonce, ProofType.JWT.getClaimTyp(), false);
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

        var offer = getCredentialWithDeeplinkResponseDto();
        var credentialOffer = extractCredentialOfferDtoFromCredentialWithDeeplinkResponseDto(
                offer);
        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, credentialOffer.getGrants().preAuthorizedCode().preAuthCode().toString());
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

        var offer = getCredentialWithDeeplinkResponseDto();
        var credentialOffer = extractCredentialOfferDtoFromCredentialWithDeeplinkResponseDto(
                offer);
        var nonce = requestNonce(mock);
        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, credentialOffer.getGrants().preAuthorizedCode().preAuthCode().toString());
        String token = (String) tokenResponse.get("access_token");
        String proof = TestServiceUtils.createHolderProof(jwk,
                applicationProperties.getTemplateReplacement().get("external-url"),
                nonce, ProofType.JWT.getClaimTyp(), false);
        String credentialRequestString = getCredentialRequestString(proof);

        var response = requestCredential(mock, token, credentialRequestString)
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.transaction_id").isNotEmpty())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
                .andReturn();

        String transactionId = JsonPath.read(response.getResponse().getContentAsString(), "$.transaction_id");
        updateStatus(mock, offer.getManagementId().toString(), UpdateCredentialStatusRequestTypeDto.READY);

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

        var offer = getCredentialWithDeeplinkResponseDto();
        var offer2 = getCredentialWithDeeplinkResponseDto();
        var credentialOffer2 = extractCredentialOfferDtoFromCredentialWithDeeplinkResponseDto(
                offer);
        var credentialOffer = extractCredentialOfferDtoFromCredentialWithDeeplinkResponseDto(
                offer2);
        var nonce = requestNonce(mock);
        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, credentialOffer.getGrants().preAuthorizedCode().preAuthCode().toString());
        String token = (String) tokenResponse.get("access_token");
        String proof = TestServiceUtils.createHolderProof(jwk,
                applicationProperties.getTemplateReplacement().get("external-url"),
                nonce, ProofType.JWT.getClaimTyp(), false);
        String credentialRequestString = getCredentialRequestString(proof);

        // wrong token
        var otherTokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock,
                credentialOffer2.getGrants().preAuthorizedCode().preAuthCode().toString());
        var otherToken = otherTokenResponse.get("access_token");

        var response = requestCredential(mock, token, credentialRequestString)
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.transaction_id").isNotEmpty())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
                .andReturn();

        String transactionId = JsonPath.read(response.getResponse().getContentAsString(), "$.transaction_id");
        updateStatus(mock, offer.getManagementId().toString(), UpdateCredentialStatusRequestTypeDto.READY);

        String deferredCredentialRequestString = getDeferredCredentialRequestString(transactionId);

        mock.perform(post(deferredCredentialEndpoint)
                        .header("Authorization", String.format("BEARER %s", otherToken))
                        .contentType("application/json")
                        .content(deferredCredentialRequestString))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("INVALID_TRANSACTION_ID"))
                .andExpect(jsonPath("$.error_description").value("Invalid transaction id"))
                .andReturn();
    }

    @Test
    void testBoundDeferredFlowWithAlreadyIssuedCredential_thenInvalidCredentialRequestException() throws Exception {

        var offer = getCredentialWithDeeplinkResponseDto();
        var credentialOffer = extractCredentialOfferDtoFromCredentialWithDeeplinkResponseDto(
                offer);
        var nonce = requestNonce(mock);
        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, credentialOffer.getGrants().preAuthorizedCode().preAuthCode().toString());
        String token = (String) tokenResponse.get("access_token");

        String proof = TestServiceUtils.createHolderProof(jwk,
                applicationProperties.getTemplateReplacement().get("external-url"),
                nonce, ProofType.JWT.getClaimTyp(), false);
        String credentialRequestString = getCredentialRequestString(proof);

        var response = requestCredential(mock, token, credentialRequestString)
                .andExpect(status().isAccepted())
                .andReturn();

        String transactionId = JsonPath.read(response.getResponse().getContentAsString(), "$.transaction_id");

        // Mock issuer management interaction
        updateStatus(mock, offer.getManagementId().toString(), UpdateCredentialStatusRequestTypeDto.READY);

        String deferredCredentialRequestString = String.format("{ \"transaction_id\": \"%s\"}}", transactionId);

        var credentialResponse = getDeferredCallResultActions(token, deferredCredentialRequestString)
                .andExpect(status().isOk())
                .andReturn();

        var vc = JsonParser.parseString(credentialResponse.getResponse().getContentAsString()).getAsJsonObject()
                .get("credential").getAsString();
        TestInfrastructureUtils.verifyVC(sdjwtProperties, vc, getUniversityCredentialSubjectData());

        getDeferredCallResultActions(token, deferredCredentialRequestString)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("INVALID_TRANSACTION_ID"))
                .andReturn();
    }

    @Test
    void testBoundDeferredFlowWithAlreadyIssuedCredential_thenRequestDeniedException() throws Exception {

        var offer = getCredentialWithDeeplinkResponseDto();
        var credentialOffer = extractCredentialOfferDtoFromCredentialWithDeeplinkResponseDto(
                offer);
        var nonce = requestNonce(mock);
        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, credentialOffer.getGrants().preAuthorizedCode().preAuthCode().toString());
        String token = (String) tokenResponse.get("access_token");

        String proof = TestServiceUtils.createHolderProof(jwk,
                applicationProperties.getTemplateReplacement().get("external-url"),
                nonce, ProofType.JWT.getClaimTyp(), false);
        String credentialRequestString = getCredentialRequestString(proof);

        var response = requestCredential(mock, token, credentialRequestString)
                .andExpect(status().isAccepted())
                .andReturn();

        String transactionId = JsonPath.read(response.getResponse().getContentAsString(), "$.transaction_id");

        // Mock issuer management interaction
        updateStatus(mock, offer.getManagementId().toString(), UpdateCredentialStatusRequestTypeDto.READY);

        String deferredCredentialRequestString = String.format("{ \"transaction_id\": \"%s\"}}", transactionId);

        // change status to CANCELLED
        updateStatus(mock, offer.getManagementId().toString(), UpdateCredentialStatusRequestTypeDto.CANCELLED);

        getDeferredCallResultActions(token, deferredCredentialRequestString)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("CREDENTIAL_REQUEST_DENIED"));
    }

    @Test
    void testDeferredOffer_noBatch_withoutProof_thenSuccess() throws Exception {

        doReturn(null).when(issuerMetadata).getBatchCredentialIssuance();
        doReturn(false).when(issuerMetadata).isBatchIssuanceAllowed();

        var unboundOffer = createUnboundCredentialOffer();
        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock,
                unboundOffer.getPreAuthorizedCode().toString());
        var token = tokenResponse.get("access_token");
        var credentialRequestString = " { \"format\": \"vc+sd-jwt\"}";

        var deferredCredentialResponse = requestCredential(mock, (String) token, credentialRequestString)
                .andExpect(status().isAccepted())
                .andExpect(content().contentType("application/json"))
                .andExpect(jsonPath("$.credentials").doesNotExist())
                .andExpect(jsonPath("$.transaction_id").isNotEmpty())
                .andReturn();

        DeferredDataDto deferredDataDto = objectMapper.readValue(
                deferredCredentialResponse.getResponse().getContentAsString(), DeferredDataDto.class);

        // check status from business issuer perspective
        updateStatus(mock, unboundOffer.getCredentialManagement().getId().toString(),
                UpdateCredentialStatusRequestTypeDto.READY);

        String deferredCredentialRequestString = getDeferredCredentialRequestString(
                deferredDataDto.transactionId().toString());

        mock.perform(post(deferredCredentialEndpoint)
                        .header("Authorization", String.format("BEARER %s", token))
                        .contentType("application/json")
                        .content(deferredCredentialRequestString))
                .andExpect(status().isOk())
                .andReturn();
    }

    @Test
    void testDeferredOffer_batched_withoutProof_thenSuccess() throws Exception {

        var unboundOffer = createUnboundCredentialOffer();
        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock,
                unboundOffer.getPreAuthorizedCode().toString());
        var token = tokenResponse.get("access_token");
        var credentialRequestString = " { \"format\": \"vc+sd-jwt\"}";

        var deferredCredentialResponse = requestCredential(mock, (String) token, credentialRequestString)
                .andExpect(status().isAccepted())
                .andExpect(content().contentType("application/json"))
                .andExpect(jsonPath("$.credentials").doesNotExist())
                .andExpect(jsonPath("$.transaction_id").isNotEmpty())
                .andReturn();

        DeferredDataDto deferredDataDto = objectMapper.readValue(
                deferredCredentialResponse.getResponse().getContentAsString(), DeferredDataDto.class);

        // check status from business issuer perspective
        mock.perform(patch("/management/api/credentials/%s/status?credentialStatus=%s".formatted(
                        unboundOffer.getCredentialManagement().getId(),
                        CredentialOfferStatusType.READY.name())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("READY"))
                .andReturn();
        updateStatus(mock, unboundOffer.getCredentialManagement().getId().toString(),
                UpdateCredentialStatusRequestTypeDto.READY);

        String deferredCredentialRequestString = getDeferredCredentialRequestString(
                deferredDataDto.transactionId().toString());

        mock.perform(post(deferredCredentialEndpoint)
                        .header("Authorization", String.format("BEARER %s", token))
                        .contentType("application/json")
                        .content(deferredCredentialRequestString))
                .andExpect(status().isOk())
                .andReturn();
    }

    @Test
    void testDeferredOffer_withDefaultDeferredExpiration_thenSuccess() throws Exception {

        var unboundOffer = createUnboundCredentialOffer();

        Instant instant = Instant.now(Clock.fixed(Instant.parse("2025-01-01T00:00:00.00Z"), ZoneId.of("UTC")));

        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock,
                unboundOffer.getPreAuthorizedCode().toString());
        var token = tokenResponse.get("access_token");

        try (MockedStatic<Instant> mockedStatic = mockStatic(Instant.class, Mockito.CALLS_REAL_METHODS)) {
            mockedStatic.when(Instant::now).thenReturn(instant);

            var nonce = requestNonce(mock);

            var credentialRequestString = getCredentialRequestString(nonce);

            requestCredential(mock, token.toString(),
                    credentialRequestString)
                    .andExpect(status().isAccepted())
                    .andReturn();

            var result = credentialOfferRepository.findByIdForUpdate(unboundOffer.getId()).orElseThrow();

            assertEquals(instant.plusSeconds(applicationProperties.getDeferredOfferValiditySeconds())
                    .getEpochSecond(), result.getOfferExpirationTimestamp());
        }
    }

    @Test
    void testDeferredOffer_withDynamicDeferredExpiration_thenSuccess() throws Exception {

        var expirationInSeconds = 1728000; // 20 days

        var offerWithDynamicExpiration = createTestOffer(UUID.randomUUID(), CredentialOfferStatusType.IN_PROGRESS, "university_example_sd_jwt", new CredentialOfferMetadata(true, null, null, null), expirationInSeconds);

        var credentialManagement = credentialManagementRepository.save(CredentialManagement.builder()
                .id(UUID.randomUUID())
                .accessToken(UUID.randomUUID())
                .credentialManagementStatus(CredentialStatusManagementType.INIT)
                .accessTokenExpirationTimestamp(Instant.now().plusSeconds(120).getEpochSecond())
                .renewalRequestCnt(0)
                .renewalResponseCnt(0)
                .build());

        offerWithDynamicExpiration.setCredentialManagement(credentialManagement);
        var storedOffer = credentialOfferRepository.save(offerWithDynamicExpiration);
        credentialOfferStatusRepository.save(linkStatusList(offerWithDynamicExpiration, statusList, 6));

        credentialManagement.addCredentialOffer(storedOffer);
        credentialManagement = credentialManagementRepository.save(credentialManagement);

        Instant instant = Instant.now(Clock.fixed(Instant.parse("2025-01-01T00:00:00.00Z"), ZoneId.of("UTC")));

        try (MockedStatic<Instant> mockedStatic = mockStatic(Instant.class, Mockito.CALLS_REAL_METHODS)) {
            mockedStatic.when(Instant::now).thenReturn(instant);

            var nonce = UUID.randomUUID() + "::" + Instant.now().minusSeconds(10L).toString();

            var credentialRequestString = getCredentialRequestStringByNonce(nonce);

            requestCredential(mock, credentialManagement.getAccessToken().toString(), credentialRequestString)
                    .andExpect(status().isAccepted())
                    .andReturn();

            var result = credentialOfferRepository.findByIdForUpdate(offerWithDynamicExpiration.getId()).orElseThrow();

            assertEquals(instant.plusSeconds(expirationInSeconds).getEpochSecond(), result.getOfferExpirationTimestamp());
        }
    }

    private StatusList saveStatusList(StatusList statusList) {
        return statusListRepository.save(statusList);
    }

    private ResultActions getDeferredCallResultActions(Object token, String deferredCredentialRequestString)
            throws Exception {
        return mock.perform(post(deferredCredentialEndpoint)
                .header("Authorization", String.format("BEARER %s", token))
                .contentType("application/json")
                .content(deferredCredentialRequestString));
    }

    private Map<String, String> getTestOfferData() {
        Map<String, String> testOfferData = new HashMap<>();
        testOfferData.put("lastName", "lastName");
        testOfferData.put("firstName", "firstName");
        testOfferData.put("dateOfBirth", "2000-01-01");
        return testOfferData;
    }

    private String getCredentialRequestString(String proof) {
        return String.format(
                "{ \"format\": \"vc+sd-jwt\" , \"proof\": {\"proof_type\": \"jwt\", \"jwt\": \"%s\"}}",
                proof);
    }

    private String getCredentialRequestStringByNonce(String nonce) throws JOSEException {
        String proof = TestServiceUtils.createHolderProof(jwk,
                applicationProperties.getTemplateReplacement().get("external-url"), nonce,
                ProofType.JWT.getClaimTyp(), false);
        return getCredentialRequestString(proof);
    }

    private String getDeferredCredentialRequestString(String transactionId) {
        return String.format("{ \"transaction_id\": \"%s\"}", transactionId);
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

    private CredentialWithDeeplinkResponseDto getCredentialWithDeeplinkResponseDto() throws Exception {
        var offerRequest = CreateCredentialOfferRequestDto.builder()
                .metadataCredentialSupportedId(List.of("university_example_sd_jwt"))
                .credentialSubjectData(getUniversityCredentialSubjectData())
                .credentialMetadata(getCredentialMetadataDto())
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

        return objectMapper.readValue(
                response.getResponse().getContentAsString(), CredentialWithDeeplinkResponseDto.class);
    }
}