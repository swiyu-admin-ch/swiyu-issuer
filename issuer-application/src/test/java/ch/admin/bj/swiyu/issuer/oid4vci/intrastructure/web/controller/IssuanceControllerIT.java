package ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.common.profile.SwissProfileVersions;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.NonceResponseDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofType;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.SelfContainedNonce;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.issuance.CredentialEndpointRequestDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.issuance.ProofsDto;
import ch.admin.bj.swiyu.issuer.oid4vci.test.TestInfrastructureUtils;
import ch.admin.bj.swiyu.issuer.service.test.TestServiceUtils;
import ch.admin.bj.swiyu.issuer.service.NonceService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static ch.admin.bj.swiyu.issuer.dto.oid4vci.CredentialRequestErrorDto.INVALID_PROOF;
import static ch.admin.bj.swiyu.issuer.dto.oid4vci.OAuthErrorDto.INVALID_GRANT;
import static ch.admin.bj.swiyu.issuer.dto.oid4vci.OAuthErrorDto.INVALID_REQUEST;
import static ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller.IssuanceV2TestUtils.requestCredentialV2;
import static ch.admin.bj.swiyu.issuer.oid4vci.test.CredentialOfferTestData.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
@Transactional
class IssuanceControllerIT {

    private static UUID offerId;
    private static StatusList testStatusList;
    private static ECKey jwk;
    private final UUID validPreAuthCode = UUID.randomUUID();
    private final UUID allValuesPreAuthCode = UUID.randomUUID();
    private final UUID unboundPreAuthCode = UUID.randomUUID();
    private final Instant validFrom = Instant.now();
    private final Instant validUntil = Instant.now().plus(30, ChronoUnit.DAYS);

    @Autowired
    private MockMvc mock;
    @Autowired
    private CredentialOfferRepository credentialOfferRepository;
    @Autowired
    private StatusListRepository statusListRepository;
    @Autowired
    private CredentialOfferStatusRepository credentialOfferStatusRepository;
    @Autowired
    private CredentialManagementRepository credentialManagementRepository;
    @Autowired
    private SdjwtProperties sdjwtProperties;
    @MockitoSpyBean
    private ApplicationProperties applicationProperties;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private NonceService nonceService;


    private static Map<String, String> getUnboundCredentialSubjectData() {
        Map<String, String> credentialSubjectData = new HashMap<>();
        credentialSubjectData.put("animal", "Tux");
        return credentialSubjectData;
    }

    private static CredentialOffer createUnboundCredentialOffer(UUID preAuthCode, CredentialOfferStatusType status) {
        var offerData = new HashMap<String, Object>();
        offerData.put("data", new GsonBuilder().create().toJson(getUnboundCredentialSubjectData()));
        return CredentialOffer.builder().credentialStatus(status)
                .metadataCredentialSupportedId(List.of("unbound_example_sd_jwt"))
                .offerData(offerData)
                .credentialMetadata(null)
                .offerExpirationTimestamp(Instant.now().plusSeconds(120).getEpochSecond())
                .nonce(UUID.randomUUID())
                .preAuthorizedCode(preAuthCode)
                .build();
    }

    @BeforeEach
    void setUp() throws JOSEException {
        testStatusList = saveStatusList(createStatusList());
        CredentialOfferMetadata metadata = new CredentialOfferMetadata(null, "vct#integrity-example", null, null);
        var offer = createTestOffer(validPreAuthCode, CredentialOfferStatusType.OFFERED, "university_example_sd_jwt", metadata);
        saveStatusListLinkedOffer(offer, testStatusList, 0);
        offerId = offer.getId();
        var allValuesPreAuthCodeOffer = createTestOffer(allValuesPreAuthCode, CredentialOfferStatusType.OFFERED, "university_example_sd_jwt", validFrom, validUntil, null);
        saveStatusListLinkedOffer(allValuesPreAuthCodeOffer, testStatusList, 1);
        var unboundOffer = createUnboundCredentialOffer(unboundPreAuthCode, CredentialOfferStatusType.OFFERED);
        saveStatusListLinkedOffer(unboundOffer, testStatusList, 2);
        jwk = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("Test-Key")
                .issueTime(new Date())
                .generate();
    }

    @Test
    void testGetIssuerMetadataWithSignedMetadata_thenSuccess() throws Exception {
        // Override with always enabled signed metadata
        when(applicationProperties.isSignedMetadataEnabled()).thenReturn(true);

        String minPayloadWithEmptySubject = String.format(
                "{\"metadata_credential_supported_id\": [\"%s\"], \"credential_subject_data\": {\"hello\": \"world\", \"lastName\": \"Example\"}}",
                "test");

        var offerResponse = mock.perform(post("/management/api/credentials").contentType(MediaType.APPLICATION_JSON).content(minPayloadWithEmptySubject))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.management_id").isNotEmpty())
                .andExpect(jsonPath("$.offer_deeplink").isNotEmpty())
                .andReturn().getResponse().getContentAsString();

        var offerObject = JsonParser.parseString(offerResponse).getAsJsonObject();

        var deeplink = offerObject.get("offer_deeplink").getAsString();

        var decodedDeeplink = URLDecoder.decode(deeplink, StandardCharsets.UTF_8);

        var credentialOffer = JsonParser.parseString(decodedDeeplink.substring(decodedDeeplink.indexOf("credential_offer=") + "credential_offer=".length()))
                .getAsJsonObject();

        var issuerUrl = credentialOffer.get("credential_issuer").getAsString();

        var response = mock.perform(get(issuerUrl.split("http://localhost:8080")[1] + "/.well-known/openid-configuration").header(HttpHeaders.ACCEPT, "application/jwt"))
                .andReturn().getResponse().getContentAsString();

        var test = SignedJWT.parse(response);

        var claims = test.getJWTClaimsSet().getClaims();
        var headers = test.getHeader();

        /*
         * alg: Must be ES256
         * typ: Must be openidvci-issuer-metadata+jwt
         * kid: Must be the time when the JWT was issued
         */
        assertEquals("ES256", headers.getAlgorithm().getName());
        assertEquals("openidvci-issuer-metadata+jwt", headers.getType().getType());
        assertEquals(sdjwtProperties.getVerificationMethod(), headers.getKeyID());
        assertEquals(SwissProfileVersions.ISSUANCE_PROFILE_VERSION, headers.getCustomParam(SwissProfileVersions.PROFILE_VERSION_PARAM));

        /*
         * sub: Must be the credential issuer identifier (generally external url)
         * iat: Must be the time when the JWT was issued
         * exp: Optional the time when the Metadata are expiring -> default 24h
         */

        assertEquals(issuerUrl, claims.get("sub"), "Subject must match the credential issuer identifier");
        assertNotNull(claims.get("iat"));
        assertNotNull(claims.get("exp"));
    }

    @Test
    void testGetNonce_thenSuccess() throws Exception {
        var selfContainedNonce = fetchSelfContainedNonce();
        assertTrue(selfContainedNonce.isValid(10));
        assertDoesNotThrow(selfContainedNonce::getNonceId);
    }

    @Test
    void testNonceReplay_thenBadRequest() throws Exception {
        var selfContainedNonce = fetchSelfContainedNonce();
        var nonce = selfContainedNonce.getNonce();
        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");

        // Nonce not yet used
        assertFalse(nonceService.isUsedNonce(selfContainedNonce));

        String proof = TestServiceUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), nonce, ProofType.JWT.getClaimTyp(), true);
        String credentialRequestString = getCredentialRequestString(proof);

        // First time OK
        requestCredentialV2(mock, (String) token, credentialRequestString)
                .andExpect(status().isOk());

        // Nonce now used
        assertTrue(nonceService.isUsedNonce(selfContainedNonce));

        // Open new Request
        var newOfferPreAuthCode = UUID.randomUUID();
        var newOffer = createTestOffer(newOfferPreAuthCode, CredentialOfferStatusType.OFFERED, "university_example_sd_jwt");
        saveStatusListLinkedOffer(newOffer, testStatusList, 5);
        tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, newOfferPreAuthCode.toString());
        token = tokenResponse.get("access_token");
        proof = TestServiceUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), nonce, ProofType.JWT.getClaimTyp(), true);
        credentialRequestString = getCredentialRequestString(proof);

        // Should BadRequest with some error hinting that proof was reused
        requestCredentialV2(mock, (String) token, credentialRequestString)
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString("proof")))
                .andExpect(content().string(containsString("reused")))
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE));
        // Should still be registered as used
        assertTrue(nonceService.isUsedNonce(selfContainedNonce));
    }

    @Test
    void testNonceOutdated_thenBadRequest() throws Exception {
        var outdatedNonce = new SelfContainedNonce(UUID.randomUUID() + "::" + Instant.now().minus(applicationProperties.getNonceLifetimeSeconds() + 1, ChronoUnit.SECONDS));
        // Outdated Nonce not valid
        assertFalse(outdatedNonce.isValid(applicationProperties.getNonceLifetimeSeconds()));
        // Create Credential Request with Proof using outdated nonce
        var nonce = outdatedNonce.getNonce();
        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");
        var proof = TestServiceUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), nonce, ProofType.JWT.getClaimTyp(), true);
        var credentialRequestString = getCredentialRequestString(proof);

        requestCredentialV2(mock, (String) token, credentialRequestString)
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString("Nonce is expired")))
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE));
        // Should not have been cached
        assertFalse(nonceService.isUsedNonce(outdatedNonce));
    }

    @ParameterizedTest
    @CsvSource({"true,", "false,", "true,did:example:override", "false,did:example:override"})
    void testCredentialFlow_thenSuccess(boolean useNewNonce, String overrideId) throws Exception {
        ConfigurationOverride override = null;
        String expectedIssuer;
        String expectedVerificationMethod;
        if (overrideId != null) {
            expectedIssuer = overrideId;
            expectedVerificationMethod = overrideId + "#key1";
            override = new ConfigurationOverride(overrideId, overrideId + "#key1", null, null);
        } else {
            expectedIssuer = applicationProperties.getIssuerId();
            expectedVerificationMethod = sdjwtProperties.getVerificationMethod();
        }
        String vc = getBoundVc(useNewNonce, override);

        TestInfrastructureUtils.verifyVC(sdjwtProperties, vc, getUniversityCredentialSubjectData());
        var jwt = SignedJWT.parse(vc.split("~")[0]);

        assertEquals(expectedIssuer, jwt.getJWTClaimsSet().getIssuer());
        assertEquals(expectedVerificationMethod, jwt.getHeader().getKeyID());
    }

    @Test
    void testNonceHeaderCacheControl_noStore() throws Exception {
        mock.perform(post("/oid4vci/api/nonce")).andExpect(status().isOk())
                // nonce cache must be at least no-store; checking that spring default which contains no-store has not been changed
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-cache, no-store, max-age=0, must-revalidate"));
    }

    @Test
    void testCredentialFlowSendIncorrectNonce_thenError() throws Exception {
        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");

        String proof = TestServiceUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), UUID.randomUUID().toString(), ProofType.JWT.getClaimTyp(), true);
        String credentialRequestString = getCredentialRequestString(proof);

        requestCredentialV2(mock, (String) token, credentialRequestString)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(INVALID_PROOF.name()))
                .andExpect(jsonPath("$.error_description").value("Nonce claim does not match the server-provided c_nonce value"))
                .andReturn();
    }

    @Test
    void testWrongProofType_thenBadRequest() throws Exception {
        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");

        String proof = TestServiceUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), tokenResponse.get("c_nonce").toString(), "wrong type", true);
        // V2 Payload
        String credentialRequestString = objectMapper.writeValueAsString(new CredentialEndpointRequestDto(
                "university_example_sd_jwt",
                new ProofsDto(List.of(proof)),
                null
        ));

        JsonObject credentialResponse = TestInfrastructureUtils.requestFailingCredential(mock, token, credentialRequestString);
        assertEquals(INVALID_PROOF.name(), credentialResponse.get("error").getAsString());
    }

    @Test
    void testHolderBindingProof_GivenIssuedAtWindowInFuture_thenBadRequest() throws Exception {
        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");
        String proof = TestServiceUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), tokenResponse.get("c_nonce").toString(), ProofType.JWT.getClaimTyp(), true, Date.from(Instant.now().plus(1, ChronoUnit.HOURS)));
        String credentialRequestString = getCredentialRequestString(proof);
        JsonObject credentialResponse = TestInfrastructureUtils.requestFailingCredential(mock, token, credentialRequestString);

        assertEquals(INVALID_PROOF.name(), credentialResponse.get("error").getAsString());
    }

    @Test
    void testHolderBindingProof_GivenIssuedAtWindowInPast_thenBadRequest() throws Exception {
        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");
        String proof = TestServiceUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), tokenResponse.get("c_nonce").toString(), ProofType.JWT.getClaimTyp(), true, Date.from(Instant.now().minus(1, ChronoUnit.HOURS)));
        String credentialRequestString = getCredentialRequestString(proof);
        JsonObject credentialResponse = TestInfrastructureUtils.requestFailingCredential(mock, token, credentialRequestString);

        assertEquals(INVALID_PROOF.name(), credentialResponse.get("error").getAsString());
    }

    @Test
    void testMissingProof_thenBadRequest() throws Exception {
        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");

        String credentialRequestString = objectMapper.writeValueAsString(new CredentialEndpointRequestDto(
                "university_example_sd_jwt",
                new ProofsDto(List.of()),
                null
        ));

        JsonObject credentialResponse = TestInfrastructureUtils.requestFailingCredential(mock, token, credentialRequestString);
        assertEquals("Unprocessable Entity", credentialResponse.get("error_description").getAsString());
    }

    @Test
    void testWithMissingProof_thenBadRequest() throws Exception {
        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");

        String credentialRequestString = objectMapper.writeValueAsString(new CredentialEndpointRequestDto(
                "university_example_sd_jwt",
                null,
                null
        ));

        requestCredentialV2(mock, (String) token, credentialRequestString)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(INVALID_PROOF.name()));
    }

    @Test
    void testUnboundCredentialFlow_thenSuccess() throws Exception {
        var vc = getUnboundVc();
        TestInfrastructureUtils.verifyVC(sdjwtProperties, vc, getUnboundCredentialSubjectData());
    }

    @Test
    void testDeprecatedTokenEndpoint_thenSuccess() throws Exception {
        mock.perform(post("/oid4vci/api/token")
                        .param("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
                        .param("pre-authorized_code", validPreAuthCode.toString()))
                .andExpect(status().isOk())
                // Assertions w.r.t. RFC 6749 ("The OAuth 2.0 Authorization Framework")
                // specified at https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(jsonPath("$.access_token").isNotEmpty()) // REQUIRED
                .andExpect(jsonPath("$.token_type").isNotEmpty()) // REQUIRED
                .andExpect(jsonPath("$.token_type").value("BEARER"));
    }

    @Test
    void testNewTokenEndpoint_thenSuccess() throws Exception {
        mock.perform(post("/oid4vci/api/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
                        .param("pre-authorized_code", validPreAuthCode.toString()))
                .andExpect(status().isOk())
                // Assertions w.r.t. RFC 6749 ("The OAuth 2.0 Authorization Framework")
                // specified at https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(jsonPath("$.access_token").isNotEmpty()) // REQUIRED
                .andExpect(jsonPath("$.token_type").isNotEmpty()) // REQUIRED
                .andExpect(jsonPath("$.token_type").value("BEARER"));
    }

    @Test
    void testInvalidPreAuthCode_thenBadRequest() throws Exception {
        var grantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

        mock.perform(post("/oid4vci/api/token")
                        .param("grant_type", grantType)
                        .param("pre-authorized_code", "aaaaaaaa-dead-dead-dead-deaddeafdead"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString(INVALID_GRANT.name())));

        // check that correct preauthcode is used
        mock.perform(post("/oid4vci/api/token")
                        .param("grant_type", grantType)
                        .param("pre-authorized_code", offerId.toString()))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString(INVALID_GRANT.name())));
    }

    @Test
    void noPreauthCode_thenException() throws Exception {
        mock.perform(post("/oid4vci/api/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code"))
                .andExpect(status().isBadRequest());

        mock.perform(post("/oid4vci/api/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
                        .param("pre-authorized_code", ""))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testInvalidGrantType_thenBadRequest() throws Exception {
        // With Valid preauth code
        mock.perform(post("/oid4vci/api/token")
                        .param("grant_type", "urn:ietf:params:oauth:grant-type:test-authorized_code")
                        .param("pre-authorized_code", "deadbeef-dead-dead-dead-deaddeafbeef"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString(INVALID_REQUEST.name())));

        // With Invalid preauth code
        mock.perform(post("/oid4vci/api/token")
                        .param("grant_type", "urn:ietf:params:oauth:grant-type:test-authorized_code")
                        .param("pre-authorized_code", "aaaaaaaa-dead-dead-dead-deaddeafdead"))
                .andExpect(status().isBadRequest())
                .andExpect(content().string(containsString(INVALID_REQUEST.name())));
    }

    private void addOverride(UUID preAuthCode, ConfigurationOverride override) {
        var offer = credentialOfferRepository.findByPreAuthorizedCode(preAuthCode);
        assert offer.isPresent();
        offer.get().setConfigurationOverride(override);
    }

    private String getBoundVc(boolean useNonceEndpoint) throws Exception {
        return getBoundVc(useNonceEndpoint, null);
    }

    private String getBoundVc(boolean useNonceEndpoint, ConfigurationOverride override) throws Exception {
        if (override != null) {
            addOverride(validPreAuthCode, override);
        }
        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");
        var nonce = tokenResponse.get("c_nonce").toString();
        if (useNonceEndpoint) {
            nonce = fetchSelfContainedNonce().getNonce();
        }

        String proof = TestServiceUtils.createHolderProof(
                jwk,
                applicationProperties.getTemplateReplacement().get("external-url"),
                nonce,
                ProofType.JWT.getClaimTyp(),
                true
        );

        String credentialRequestString = getCredentialRequestString(proof);
        return extractVcFromV2CredentialResponse(
                requestCredentialV2(mock, (String) token, credentialRequestString)
                        .andExpect(status().isOk())
                        .andReturn()
        );
    }

    private String getUnboundVc() throws Exception {
        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, unboundPreAuthCode.toString());
        var token = tokenResponse.get("access_token");

        String credentialRequestString = String.format(
                "{\"credential_configuration_id\":\"%s\"}",
                "unbound_example_sd_jwt"
        );

        return extractVcFromV2CredentialResponse(
                requestCredentialV2(mock, (String) token, credentialRequestString)
                        .andExpect(status().isOk())
                        .andReturn()
        );
    }

    private String getCredentialRequestString(String proof) throws Exception {
        var request = new CredentialEndpointRequestDto(
                "university_example_sd_jwt",
                new ProofsDto(List.of(proof)),
                null
        );
        return objectMapper.writeValueAsString(request);
    }

    private static String extractVcFromV2CredentialResponse(MvcResult credentialResponse) throws UnsupportedEncodingException {
        var credentials = JsonParser.parseString(credentialResponse.getResponse().getContentAsString())
                .getAsJsonObject()
                .getAsJsonArray("credentials");
        return credentials.get(0).getAsJsonObject().get("credential").getAsString();
    }

    private CredentialOffer saveStatusListLinkedOffer(CredentialOffer offer, StatusList statusList, int index) {
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
        return storedOffer;
    }

    private StatusList saveStatusList(StatusList statusList) {
        return statusListRepository.save(statusList);
    }


    @NotNull
    private SelfContainedNonce fetchSelfContainedNonce() throws Exception {
        var nonceResponse = mock.perform(post("/oid4vci/api/nonce")).andExpect(status().isOk()).andReturn();
        var nonceDto = objectMapper.readValue(nonceResponse.getResponse().getContentAsString(), NonceResponseDto.class);
        return new SelfContainedNonce(nonceDto.nonce());
    }
}

