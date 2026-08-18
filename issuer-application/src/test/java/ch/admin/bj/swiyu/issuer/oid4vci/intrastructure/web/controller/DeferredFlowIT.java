package ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.AttackPotentialResistance;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofType;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.SelfContainedNonce;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.BatchCredentialIssuance;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.dto.credentialoffer.CreateCredentialOfferRequestDto;
import ch.admin.bj.swiyu.issuer.dto.credentialoffer.CredentialOfferDto;
import ch.admin.bj.swiyu.issuer.dto.credentialoffer.CredentialOfferMetadataDto;
import ch.admin.bj.swiyu.issuer.dto.credentialoffer.CredentialWithDeeplinkResponseDto;
import ch.admin.bj.swiyu.issuer.dto.credentialofferstatus.UpdateCredentialStatusRequestTypeDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.CredentialRequestErrorDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.CredentialResponseEncryptionDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.NonceResponseDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.OAuthTokenDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.issuance.CreateCredentialRequestDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.issuance.DeferredCredentialResponseDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.issuance.ProofsDto;
import ch.admin.bj.swiyu.issuer.oid4vci.test.TestInfrastructureUtils;
import ch.admin.bj.swiyu.issuer.service.NonceService;
import ch.admin.bj.swiyu.issuer.service.did.DidKeyResolverFacade;
import ch.admin.bj.swiyu.issuer.service.test.TestServiceUtils;
import ch.admin.bj.swiyu.issuer.service.webhook.AsyncCredentialEventHandler;
import ch.admin.bj.swiyu.issuer.service.webhook.DeferredEvent;
import ch.admin.bj.swiyu.issuer.service.webhook.OfferStateChangeEvent;
import com.google.gson.JsonParser;
import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Testcontainers;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.io.UnsupportedEncodingException;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.*;
import java.util.stream.IntStream;

import static ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller.IssuanceTestUtils.requestCredentialFromDeferred;
import static ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller.IssuanceTestUtils.updateStatus;
import static ch.admin.bj.swiyu.issuer.oid4vci.test.CredentialOfferTestData.*;
import static ch.admin.bj.swiyu.issuer.oid4vci.test.TestInfrastructureUtils.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
class DeferredFlowIT {

    private static ECKey jwk;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final String configId = "university_example_sd_jwt";
    @MockitoBean
    DidKeyResolverFacade didKeyResolver;
    @MockitoSpyBean
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
    @Autowired
    private NonceService nonceService;
    private StatusList statusList;

    public static Map<String, String> getUniversityCredentialSubjectData() {
        Map<String, String> credentialSubjectData = new HashMap<>();
        credentialSubjectData.put("type", "Bachelor of Science");
        credentialSubjectData.put("name", "Data Science");
        credentialSubjectData.put("average_grade", "Data Science");
        return credentialSubjectData;
    }

    private static String getVcStringFromResponse(MvcResult credentialResponse) throws UnsupportedEncodingException {
        var credentials = JsonParser.parseString(credentialResponse.getResponse().getContentAsString())
                .getAsJsonObject()
                .getAsJsonArray("credentials");
        return credentials.get(0).getAsJsonObject().get("credential").getAsString();
    }

    private String getVcStringFromResponse(MvcResult credentialResponse, boolean encryptionEnabled, ECKey holderEncryptionKey) throws UnsupportedEncodingException, ParseException, JOSEException {

        var response = decryptIfNecessary(credentialResponse, encryptionEnabled ? holderEncryptionKey : null);

        var credentials = JsonParser.parseString(response)
                .getAsJsonObject()
                .getAsJsonArray("credentials");
        return credentials.get(0).getAsJsonObject().get("credential").getAsString();
    }

    @BeforeEach
    void setUp() throws JOSEException {
        // Reset spies so that stubs set in individual tests (e.g. getBatchCredentialIssuance=null)
        // do not bleed into subsequent tests that rely on the real bean behaviour.
        Mockito.reset(issuerMetadata);
        Mockito.reset(testEventListener);
        cleanDatabase();
        statusList = saveStatusList(createStatusList());

        jwk = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("Test-Key")
                .issueTime(new Date())
                .generate();
    }

    @AfterEach
    void tearDown() {
        cleanDatabase();
    }

    private void cleanDatabase() {
        credentialOfferStatusRepository.deleteAll();
        credentialOfferRepository.deleteAll();
        credentialManagementRepository.deleteAll();
        statusListRepository.deleteAll();
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void testCompleteFlow_thenSuccess(boolean encryptionEnabled) throws Exception {

        var credentialWithDeeplinkResponseDto = getCredentialWithDeeplinkResponseDto();

        var credentialOffer = extractCredentialOfferDtoFromCredentialWithDeeplinkResponseDto(
                credentialWithDeeplinkResponseDto);

        var metadata = getIssuerMetadata(credentialOffer);

        JWEAlgorithm alg = JWEAlgorithm.parse(metadata.getResponseEncryption().getAlgValuesSupported().getFirst());
        var holderEncryptionKey = assertDoesNotThrow(() -> new ECKeyGenerator(Curve.P_256).keyID("HolderEncryptionKey")
                .keyUse(KeyUse.ENCRYPTION)
                .algorithm(alg)
                .generate());

        // create holder keys (as many as possible defined by metadata)
        var holderBindingKeys = IntStream.range(0, metadata.getIssuanceBatchSize())
                .boxed()
                .map(i -> assertDoesNotThrow(() -> new ECKeyGenerator(Curve.P_256).keyID("HolderBindingKey#%s".formatted(i))
                        .keyUse(KeyUse.SIGNATURE)
                        .generate()))
                .toList();

        var holderBindingJwts = holderBindingKeys.stream()
                .map(holderBindingKey -> createHolderBindingJwt(holderBindingKey, issuerMetadata.getCredentialIssuer(), issuerMetadata))
                .map(SignedJWT::serialize)
                .toList();

        var tokenResponse = fetchOAuthToken(mock, credentialOffer.getGrants().preAuthorizedCode().preAuthCode().toString());
        OAuthTokenDto oauthTokenDto = objectMapper.convertValue(tokenResponse, OAuthTokenDto.class);

        String token = oauthTokenDto.getAccessToken();

        awaitHandleOfferStateChangeEvent(1);

        // prepare vc request
        var request = encryptionEnabled ? getEncryptedRequestString(metadata, holderEncryptionKey, holderBindingJwts) : getCredentialRequestString(holderBindingJwts.getFirst());

        // vc request accepted -> deferred
        var encryptedDeferredCredentialResponse = TestInfrastructureUtils.requestCredential(mock, token, request, encryptionEnabled ? "application/jwt" : "application/json")
                .andExpect(status().isAccepted()).andReturn();

        awaitHandleDeferredEvent(1);

        var deferredCredentialResponse = decryptIfNecessary(encryptedDeferredCredentialResponse, encryptionEnabled ? holderEncryptionKey : null);

        DeferredCredentialResponseDto deferredCredentialResponseDto = objectMapper.readValue(deferredCredentialResponse, DeferredCredentialResponseDto.class);

        assertNotNull(deferredCredentialResponseDto.transactionId());

        // check status from business issuer perspective
        var id = String.valueOf(credentialWithDeeplinkResponseDto.getManagementId());
        checkStatus(id, "DEFERRED");

        mock.perform(get("/management/api/credentials/" + credentialWithDeeplinkResponseDto.getManagementId()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("DEFERRED"))
                .andExpect(jsonPath("$.credential_offers[0].holder_jwks[0]")
                        .value(holderBindingKeys.getFirst().toPublicJWK().toJSONString()))
                .andExpect(jsonPath("$.credential_offers[0].key_attestations").doesNotExist())
                .andReturn();

        updateStatus(mock, credentialWithDeeplinkResponseDto.getManagementId().toString(), UpdateCredentialStatusRequestTypeDto.READY);

        // check status from business issuer perspective
        checkStatus(id, "READY");

        String deferredCredentialRequestString = getDeferredCredentialRequestString(
                deferredCredentialResponseDto.transactionId());

        var credentialResponse = requestCredentialFromDeferred(mock, token, deferredCredentialRequestString)
                .andExpect(status().isOk())
                .andReturn();
        // -> Claming_in_Progress -> Deferred -> Ready -> Issued
        awaitHandleOfferStateChangeEvent(4);

        var vc = getVcStringFromResponse(credentialResponse, encryptionEnabled, holderEncryptionKey);
        TestInfrastructureUtils.verifyVC(sdjwtProperties, vc, getUniversityCredentialSubjectData());
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void testCompleteFlow_withAndWithoutBatching_thenSuccess(boolean isBatched) throws Exception {

        if (isBatched) {
            doReturn(new BatchCredentialIssuance(10)).when(issuerMetadata).getBatchCredentialIssuance();
            doReturn(true).when(issuerMetadata).isBatchIssuanceAllowed();
        }

        var holderBindingKeys = IntStream.range(0, issuerMetadata.getIssuanceBatchSize())
                .boxed()
                .map(i -> assertDoesNotThrow(() -> new ECKeyGenerator(Curve.P_256).keyID("HolderBindingKey#%s".formatted(i))
                        .keyUse(KeyUse.SIGNATURE)
                        .generate()))
                .toList();

        var holderBindingJwts = holderBindingKeys.stream()
                .map(holderBindingKey -> createHolderBindingJwt(holderBindingKey, issuerMetadata.getCredentialIssuer(), issuerMetadata))
                .map(SignedJWT::serialize)
                .toList();

        var offerRequest = CreateCredentialOfferRequestDto.builder()
                .metadataCredentialSupportedId(List.of(configId))
                .credentialSubjectData(getUniversityCredentialSubjectData())
                .credentialMetadata(getDeferredCredentialMetadataDto())
                .build();

        // create initial credential offer
        var credentialWithDeeplinkResponseDto = createInitialCredentialWithDeeplinkResponse(mock, offerRequest);

        var credentialOffer = extractCredentialOfferDtoFromCredentialWithDeeplinkResponseDto(
                credentialWithDeeplinkResponseDto);

        var tokenDto = fetchOAuthToken(mock, credentialOffer.getGrants().preAuthorizedCode().preAuthCode().toString());

        var token = (String) tokenDto.get("access_token");

        var deferredCredentialResponse = TestInfrastructureUtils.requestCredential(mock, token,
                        getCredentialRequestString(holderBindingJwts.getFirst()), "application/json")
                .andExpect(status().isAccepted())
                .andReturn();
        awaitHandleDeferredEvent(1);

        DeferredCredentialResponseDto deferredCredentialResponseDto = objectMapper.readValue(
                deferredCredentialResponse.getResponse().getContentAsString(), DeferredCredentialResponseDto.class);

        String deferredCredentialRequestString = getDeferredCredentialRequestString(
                deferredCredentialResponseDto.transactionId());

        updateStatus(mock, credentialWithDeeplinkResponseDto.getManagementId().toString(), UpdateCredentialStatusRequestTypeDto.READY);

        requestCredentialFromDeferred(mock, token, deferredCredentialRequestString)
                .andExpect(status().isOk());
    }

    @Test
    void testCompleteFlow_withKeyAttestation_thenSuccess() throws Exception {

        Mockito.when(didKeyResolver.resolveKey(Mockito.any())).thenReturn(jwk.toPublicJWK());

        var credentialWithDeeplinkResponseDto = getCredentialWithDeeplinkResponseDto();
        var credentialOffer = extractCredentialOfferDtoFromCredentialWithDeeplinkResponseDto(
                credentialWithDeeplinkResponseDto);

        var tokenDto = TestInfrastructureUtils.fetchOAuthToken(mock, credentialOffer.getGrants().preAuthorizedCode().preAuthCode().toString());
        var nonce = requestNonce(mock);

        String proof = TestServiceUtils.createAttestedHolderProof(
                jwk,
                applicationProperties.getTemplateReplacement().get("external-url"),
                nonce,
                ProofType.JWT.getClaimTyp(),
                AttackPotentialResistance.ISO_18045_HIGH,
                null);

        var token = (String) tokenDto.get("access_token");

        var deferredCredentialResponse = TestInfrastructureUtils.requestCredential(mock, token, getCredentialRequestString(proof), "application/json")
                .andExpect(status().isAccepted())
                .andReturn();

        DeferredCredentialResponseDto deferredCredentialResponseDto = objectMapper.readValue(
                deferredCredentialResponse.getResponse().getContentAsString(), DeferredCredentialResponseDto.class);

        assertNotNull(deferredCredentialResponseDto.transactionId());

        // check status from business issuer perspective
        checkStatus(String.valueOf(credentialWithDeeplinkResponseDto.getManagementId()), "DEFERRED");

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
        checkStatus(String.valueOf(credentialWithDeeplinkResponseDto.getManagementId()), "READY");

        String deferredCredentialRequestString = getDeferredCredentialRequestString(
                deferredCredentialResponseDto.transactionId());

        var credentialResponse = requestCredentialFromDeferred(mock, token, deferredCredentialRequestString)
                .andExpect(status().isOk())
                .andReturn();

        var vc = getVcStringFromResponse(credentialResponse);
        TestInfrastructureUtils.verifyVC(sdjwtProperties, vc, getUniversityCredentialSubjectData());
    }

    @Test
    void testOfferCreation_withMissingMandatoryClaim() throws Exception {

        var extendedOfferData = new HashMap<String, Object>(getUniversityCredentialSubjectData());
        var missingClaim = "name";
        extendedOfferData.remove(missingClaim); // removing required claim

        var offerRequest = CreateCredentialOfferRequestDto.builder()
                .metadataCredentialSupportedId(List.of(configId))
                .credentialMetadata(getDeferredCredentialMetadataDto())
                .credentialSubjectData(extendedOfferData)
                .build();

        var offerRequestString = objectMapper.writeValueAsString(offerRequest);

        // create initial credential offer
        createCredentialOffer(mock, offerRequestString)
                .andExpect(status().is4xxClientError())
                .andExpect(jsonPath("$.detail")
                        .value("Mandatory credential claims are missing: [" + missingClaim + "]"))
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
        getDeferredCallResultActions(token, deferredCredentialRequestString)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(CredentialRequestErrorDto.INVALID_TRANSACTION_ID.getErrorCode()))
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
                nonce, ProofType.JWT.getClaimTyp());
        String credentialRequestString = getCredentialRequestString(proof);

        var response = TestInfrastructureUtils.requestCredential(mock, token, credentialRequestString, "application/json")
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.transaction_id").isNotEmpty())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
                .andReturn();

        String transactionId = JsonPath.read(response.getResponse().getContentAsString(), "$.transaction_id");
        updateStatus(mock, offer.getManagementId().toString(), UpdateCredentialStatusRequestTypeDto.READY);

        String deferredCredentialRequestString = getDeferredCredentialRequestString(transactionId);

        getDeferredCallResultActions(UUID.randomUUID().toString(), deferredCredentialRequestString)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_token"))
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
                nonce, ProofType.JWT.getClaimTyp());
        String credentialRequestString = getCredentialRequestString(proof);

        // wrong token
        var otherTokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock,
                credentialOffer2.getGrants().preAuthorizedCode().preAuthCode().toString());
        var otherToken = otherTokenResponse.get("access_token");

        var response = TestInfrastructureUtils.requestCredential(mock, token, credentialRequestString, "application/json")
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.transaction_id").isNotEmpty())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
                .andReturn();

        String transactionId = JsonPath.read(response.getResponse().getContentAsString(), "$.transaction_id");
        updateStatus(mock, offer.getManagementId().toString(), UpdateCredentialStatusRequestTypeDto.READY);

        String deferredCredentialRequestString = getDeferredCredentialRequestString(transactionId);

        getDeferredCallResultActions(otherToken, deferredCredentialRequestString)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(CredentialRequestErrorDto.INVALID_TRANSACTION_ID.getErrorCode()))
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
                nonce, ProofType.JWT.getClaimTyp());
        String credentialRequestString = getCredentialRequestString(proof);

        var response = TestInfrastructureUtils.requestCredential(mock, token, credentialRequestString, "application/json")
                .andExpect(status().isAccepted())
                .andReturn();

        String transactionId = JsonPath.read(response.getResponse().getContentAsString(), "$.transaction_id");

        // Mock issuer management interaction
        updateStatus(mock, offer.getManagementId().toString(), UpdateCredentialStatusRequestTypeDto.READY);

        String deferredCredentialRequestString = String.format("{ \"transaction_id\": \"%s\"}", transactionId);

        var credentialResponse = getDeferredCallResultActions(token, deferredCredentialRequestString)
                .andExpect(status().isOk())
                .andReturn();

        var vc = getVcStringFromResponse(credentialResponse);
        TestInfrastructureUtils.verifyVC(sdjwtProperties, vc, getUniversityCredentialSubjectData());

        getDeferredCallResultActions(token, deferredCredentialRequestString)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(CredentialRequestErrorDto.INVALID_TRANSACTION_ID.getErrorCode()))
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
                nonce, ProofType.JWT.getClaimTyp());
        String credentialRequestString = getCredentialRequestString(proof);

        var response = TestInfrastructureUtils.requestCredential(mock, token, credentialRequestString, "application/json")
                .andExpect(status().isAccepted())
                .andReturn();

        String transactionId = JsonPath.read(response.getResponse().getContentAsString(), "$.transaction_id");

        // Mock issuer management interaction
        updateStatus(mock, offer.getManagementId().toString(), UpdateCredentialStatusRequestTypeDto.READY);

        String deferredCredentialRequestString = String.format("{ \"transaction_id\": \"%s\"}", transactionId);

        // change status to CANCELLED
        updateStatus(mock, offer.getManagementId().toString(), UpdateCredentialStatusRequestTypeDto.CANCELLED);

        getDeferredCallResultActions(token, deferredCredentialRequestString)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(CredentialRequestErrorDto.CREDENTIAL_REQUEST_DENIED.getErrorCode()));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void testDeferredOffer_withoutProof_thenSuccess(boolean batched) throws Exception {

        if (!batched) {
            doReturn(null).when(issuerMetadata).getBatchCredentialIssuance();
            doReturn(false).when(issuerMetadata).isBatchIssuanceAllowed();
        }

        var unboundOffer = createUnboundCredentialOffer();
        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock,
                unboundOffer.getPreAuthorizedCode().toString());
        var token = (String) tokenResponse.get("access_token");
        var credentialRequestString = objectMapper.writeValueAsString(new CreateCredentialRequestDto(
                "unbound_example_sd_jwt",
                null,
                null
        ));

        var deferredCredentialResponse = TestInfrastructureUtils.requestCredential(mock, (String) token, credentialRequestString, "application/json")
                .andExpect(status().isAccepted())
                .andExpect(content().contentType("application/json"))
                .andExpect(jsonPath("$.credentials").doesNotExist())
                .andExpect(jsonPath("$.transaction_id").isNotEmpty())
                .andReturn();

        DeferredCredentialResponseDto deferredCredentialResponseDto = objectMapper.readValue(
                deferredCredentialResponse.getResponse().getContentAsString(), DeferredCredentialResponseDto.class);

        // check status from business issuer perspective
        updateStatus(mock, unboundOffer.getCredentialManagement().getId().toString(),
                UpdateCredentialStatusRequestTypeDto.READY);

        String deferredCredentialRequestString = getDeferredCredentialRequestString(
                deferredCredentialResponseDto.transactionId());

        getDeferredCallResultActions(token, deferredCredentialRequestString)
                .andExpect(status().isOk())
                .andReturn();
    }

    @Test
    void testDeferredOffer_withDefaultDeferredExpiration_thenSuccess() throws Exception {

        var unboundOffer = createUnboundCredentialOffer();

        Instant instant = Instant.now(Clock.fixed(Instant.parse("2025-01-01T00:00:00.00Z"), ZoneId.of("UTC")));

        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, unboundOffer.getPreAuthorizedCode().toString());
        var token = (String) tokenResponse.get("access_token");

        try (MockedStatic<Instant> mockedStatic = mockStatic(Instant.class, Mockito.CALLS_REAL_METHODS)) {
            mockedStatic.when(Instant::now).thenReturn(instant);

            var credentialRequestString = "{\"credential_configuration_id\": \"unbound_example_sd_jwt\"}";

            TestInfrastructureUtils.requestCredential(mock, token, credentialRequestString, "application/json")
                    .andExpect(status().isAccepted())
                    .andReturn();

            var result = Objects.requireNonNull(transactionTemplate.execute(status ->
                    credentialOfferRepository.findByIdForUpdate(unboundOffer.getId()).orElseThrow()));

            assertEquals(instant.plusSeconds(applicationProperties.getDeferredOfferValiditySeconds())
                    .getEpochSecond(), result.getOfferExpirationTimestamp());
        }
    }

    @Test
    void testDeferredOffer_withDynamicDeferredExpiration_thenSuccess() throws Exception {

        var expirationInSeconds = 1728000; // 20 days

        var offerWithDynamicExpiration = createTestOffer(UUID.randomUUID(), CredentialOfferStatusType.IN_PROGRESS, configId, new CredentialOfferMetadata(true, null, null), expirationInSeconds);

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

            var preNonce = UUID.randomUUID() + "::" + Instant.now().minusSeconds(10L).toString();
            var nonce = preNonce + "::" + SelfContainedNonce.createSignature(preNonce, nonceService.getNonceSecret());
            var credentialRequestString = getCredentialRequestStringByNonce(nonce);

            TestInfrastructureUtils.requestCredential(mock, credentialManagement.getAccessToken().toString(), credentialRequestString, "application/json")
                    .andExpect(status().isAccepted())
                    .andReturn();

            var result = Objects.requireNonNull(transactionTemplate.execute(status ->
                    credentialOfferRepository.findByIdForUpdate(offerWithDynamicExpiration.getId()).orElseThrow()));

            assertEquals(instant.plusSeconds(expirationInSeconds).getEpochSecond(), result.getOfferExpirationTimestamp());
        }
    }

    private StatusList saveStatusList(StatusList statusList) {
        return statusListRepository.save(statusList);
    }

    /**
     * Polls until the async event handler has been invoked at least {@code times} times
     * for {@link OfferStateChangeEvent}.
     */
    private void awaitHandleOfferStateChangeEvent(int times) {
        Awaitility.await()
                .atMost(Duration.ofSeconds(5))
                .pollInterval(Duration.ofMillis(100))
                .untilAsserted(() ->
                        verify(testEventListener, Mockito.atLeast(times))
                                .handleOfferStateChangeEvent(any(OfferStateChangeEvent.class)));
    }

    /**
     * Polls until the async event handler has been invoked at least {@code times} times
     * for {@link DeferredEvent}.
     */
    private void awaitHandleDeferredEvent(int times) {
        Awaitility.await()
                .atMost(Duration.ofSeconds(5))
                .pollInterval(Duration.ofMillis(100))
                .untilAsserted(() ->
                        verify(testEventListener, Mockito.atLeast(times))
                                .handleDeferredEvent(any(DeferredEvent.class)));
    }

    private ResultActions getDeferredCallResultActions(Object token, String deferredCredentialRequestString)
            throws Exception {
        String deferredCredentialEndpoint = "/oid4vci/api/deferred_credential";
        return mock.perform(post(deferredCredentialEndpoint)
                .header("Authorization", String.format("BEARER %s", token))
                .contentType("application/json")
                .content(deferredCredentialRequestString));
    }

    private String getEncryptedRequestString(IssuerMetadata metadata, ECKey holderEncryptionKeys, List<String> holderBindingJwts) throws ParseException {

        var credentialRequestDto = new CreateCredentialRequestDto(
                configId,
                new ProofsDto(holderBindingJwts),
                new CredentialResponseEncryptionDto(
                        holderEncryptionKeys.toPublicJWK()
                                .toJSONObject(),
                        metadata.getResponseEncryption()
                                .getEncValuesSupported()
                                .getFirst()
                )
        );

        var requestEncryption = metadata.getRequestEncryption();
        JWEAlgorithm alg = JWEAlgorithm.parse(metadata.getResponseEncryption().getAlgValuesSupported().getFirst());
        EncryptionMethod enc = EncryptionMethod.parse(metadata.getResponseEncryption().getEncValuesSupported().getFirst());
        JsonNode jwks = objectMapper.convertValue(requestEncryption.getJwks(), JsonNode.class);
        var key = jwks.get("keys").asArray().get(0);

        JWK requestedJWK = JWK.parse(objectMapper.writeValueAsString(key));
        var encryptedCredentialRequest = assertDoesNotThrow(() -> new EncryptedJWT(new JWEHeader.Builder(alg, enc).keyID(requestedJWK.getKeyID())
                .compressionAlgorithm(CompressionAlgorithm.DEF)
                .build(),
                JWTClaimsSet.parse(objectMapper.writeValueAsString(credentialRequestDto))));
        assertDoesNotThrow(() -> encryptedCredentialRequest.encrypt(new ECDHEncrypter(requestedJWK.toECKey())));

        return encryptedCredentialRequest.serialize();
    }

    private String getCredentialRequestString(String proof) {

        var request = new CreateCredentialRequestDto(
                configId,
                new ProofsDto(List.of(proof)),
                null
        );
        return objectMapper.writeValueAsString(request);
    }

    private SignedJWT createHolderBindingJwt(ECKey holderBindingKey,
                                             String baseIssuerUri,
                                             IssuerMetadata issuerMetadata) {
        // We need a fresh nonce for the holder binding proofs
        var nonceResponse = assertDoesNotThrow(() -> mock.perform(post(issuerMetadata.getNonceEndpoint()
                                .replace(baseIssuerUri, "")))
                        .andExpect(status().isOk())
                        .andReturn(),
                "Should be able to successfully request token using token endpoint from well-known uri"
        );

        var nonce = assertDoesNotThrow(() -> objectMapper.readValue(nonceResponse.getResponse().getContentAsString(), NonceResponseDto.class)).nonce();

        var credConfig = issuerMetadata.getCredentialConfigurationSupported().get(configId);
        JWSAlgorithm jwsAlg = JWSAlgorithm.parse(credConfig.getCredentialSigningAlgorithmsSupported().getFirst());

        var holderBindingJwt = new SignedJWT(
                new JWSHeader.Builder(jwsAlg)
                        .type(new JOSEObjectType("openid4vci-proof+jwt"))
                        .jwk(holderBindingKey.toPublicJWK())
                        .build(),
                new JWTClaimsSet.Builder()
                        .audience(issuerMetadata.getCredentialIssuer())
                        .issueTime(new Date())
                        .claim("nonce", nonce)
                        .build()
        );
        assertDoesNotThrow(() -> holderBindingJwt.sign(new ECDSASigner(holderBindingKey)),
                "Signing the wallet holder binding proof with the wallet key");
        return holderBindingJwt;
    }

    private String getCredentialRequestStringByNonce(String nonce) throws Exception {
        String proof = TestServiceUtils.createHolderProof(jwk,
                applicationProperties.getTemplateReplacement().get("external-url"), nonce,
                ProofType.JWT.getClaimTyp());
        return getCredentialRequestString(proof);
    }

    private String getDeferredCredentialRequestString(String transactionId) {
        return String.format("{ \"transaction_id\": \"%s\"}", transactionId);
    }

    private CredentialOffer createUnboundCredentialOffer() throws Exception {
        var offerMetadata = new CredentialOfferMetadataDto(true,
                "sha256-SVHLfKfcZcBrw+d9EL/1EXxvGCdkQ7tMGvZmd0ysMck=", null);
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
                .metadataCredentialSupportedId(List.of(configId))
                .credentialSubjectData(getUniversityCredentialSubjectData())
                .credentialMetadata(getDeferredCredentialMetadataDto())
                .build();

        var offerRequestString = objectMapper.writeValueAsString(offerRequest);

        return objectMapper.readValue(
                createCredentialOffer(mock, offerRequestString).andReturn().getResponse().getContentAsString(),
                CredentialWithDeeplinkResponseDto.class);
    }

    private void checkStatus(String id, String result) {
        assertDoesNotThrow(() -> mock.perform(get("/management/api/credentials/" + id + "/status"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(result)));
    }

    private IssuerMetadata getIssuerMetadata(CredentialOfferDto dto) {
        var uri = dto.getCredentialIssuer();
        var issuerMetadataResponse = assertDoesNotThrow(() -> mock.perform(get(
                        "%s/.well-known/openid-credential-issuer".formatted(uri))
                        .accept("application/jwt"))
                .andExpect(status().isOk())
                .andReturn());

        var issuerMetadataJwt = assertDoesNotThrow(() -> SignedJWT.parse(issuerMetadataResponse.getResponse()
                .getContentAsString()), "Well Known data should be a parsable JWT");

        return assertDoesNotThrow(() -> objectMapper.readValue(issuerMetadataJwt.getPayload().toString(),
                IssuerMetadata.class));
    }

    private String decryptIfNecessary(MvcResult response, ECKey holderEncryptionKeys) throws UnsupportedEncodingException, ParseException, JOSEException {
        var decrypted = response.getResponse().getContentAsString();
        if (holderEncryptionKeys != null) {
            var credentialResponseJwt = EncryptedJWT.parse(decrypted);
            credentialResponseJwt.decrypt(new ECDHDecrypter(holderEncryptionKeys.toECKey()));
            decrypted = credentialResponseJwt.getJWTClaimsSet()
                    .toString();
        }

        return decrypted;
    }
}