/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.api.oid4vci.NonceResponseDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.OAuthTokenDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofType;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.SelfContainedNonce;
import ch.admin.bj.swiyu.issuer.oid4vci.test.TestInfrastructureUtils;
import ch.admin.bj.swiyu.issuer.oid4vci.test.TestServiceUtils;
import ch.admin.bj.swiyu.issuer.service.NonceService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import lombok.NonNull;
import org.hamcrest.Matchers;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.AdditionalMatchers;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

import static ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialRequestErrorDto.INVALID_PROOF;
import static ch.admin.bj.swiyu.issuer.api.oid4vci.OAuthErrorDto.INVALID_GRANT;
import static ch.admin.bj.swiyu.issuer.api.oid4vci.OAuthErrorDto.INVALID_REQUEST;
import static ch.admin.bj.swiyu.issuer.oid4vci.test.CredentialOfferTestData.*;
import static ch.admin.bj.swiyu.issuer.oid4vci.test.TestInfrastructureUtils.requestCredential;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
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

    private static CredentialOffer createUnboundCredentialOffer(UUID preAuthCode, CredentialStatusType status) {
        var offerData = new HashMap<String, Object>();
        offerData.put("data", new GsonBuilder().create().toJson(getUnboundCredentialSubjectData()));
        return CredentialOffer.builder().credentialStatus(status)
                .metadataCredentialSupportedId(List.of("unbound_example_sd_jwt"))
                .offerData(offerData)
                .credentialMetadata(null)
                .accessToken(UUID.randomUUID())
                .tokenExpirationTimestamp(Instant.now().plusSeconds(600).getEpochSecond())
                .offerExpirationTimestamp(Instant.now().plusSeconds(120).getEpochSecond())
                .nonce(UUID.randomUUID())
                .preAuthorizedCode(preAuthCode)
                .build();
    }

    @BeforeEach
    void setUp() throws JOSEException {
        testStatusList = saveStatusList(createStatusList());
        CredentialOfferMetadata metadata = new CredentialOfferMetadata(null, "vct#integrity-example", null, null);
        var offer = createTestOffer(validPreAuthCode, CredentialStatusType.OFFERED, "university_example_sd_jwt", metadata);
        saveStatusListLinkedOffer(offer, testStatusList, 0);
        offerId = offer.getId();
        var allValuesPreAuthCodeOffer = createTestOffer(allValuesPreAuthCode, CredentialStatusType.OFFERED, "university_example_sd_jwt", validFrom, validUntil, null);
        saveStatusListLinkedOffer(allValuesPreAuthCodeOffer, testStatusList, 1);
        var unboundOffer = createUnboundCredentialOffer(unboundPreAuthCode, CredentialStatusType.OFFERED);
        saveStatusListLinkedOffer(unboundOffer, testStatusList, 2);
        jwk = new ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .keyID("Test-Key")
                .issueTime(new Date())
                .generate();
    }

    @Test
    void testGetIssuerMetadataWithSignedMetadata_thenSuccess() throws Exception {

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

        /*
         * sub: Must match the issuer did
         * iat: Must be the time when the JWT was issued
         * exp: Optional the time when the Metadata are expiring -> default 24h
         */

        assertEquals(applicationProperties.getIssuerId(), claims.get("sub"));
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
        String credentialRequestString = String.format("{ \"format\": \"vc+sd-jwt\" , \"proof\": {\"proof_type\": \"jwt\", \"jwt\": \"%s\"}}", proof);
        // First time OK
        TestInfrastructureUtils.getCredential(mock, token, credentialRequestString);

        // Nonce now used
        assertTrue(nonceService.isUsedNonce(selfContainedNonce));

        // Open new Request
        var newOfferPreAuthCode = UUID.randomUUID();
        var newOffer = createTestOffer(newOfferPreAuthCode, CredentialStatusType.OFFERED, "university_example_sd_jwt");
        saveStatusListLinkedOffer(newOffer, testStatusList, 5);
        tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, newOfferPreAuthCode.toString());
        token = tokenResponse.get("access_token");
        proof = TestServiceUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), nonce, ProofType.JWT.getClaimTyp(), true);
        credentialRequestString = String.format("{ \"format\": \"vc+sd-jwt\" , \"proof\": {\"proof_type\": \"jwt\", \"jwt\": \"%s\"}}", proof);
        // Should BadRequest with some error hinting that proof was reused
        requestCredential(mock, (String) token, credentialRequestString)
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
        var credentialRequestString = String.format("{ \"format\": \"vc+sd-jwt\" , \"proof\": {\"proof_type\": \"jwt\", \"jwt\": \"%s\"}}", proof);
        // Should BadRequest with some error hinting that proof was reused
        requestCredential(mock, (String) token, credentialRequestString)
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
        String credentialRequestString = String.format("{ \"format\": \"vc+sd-jwt\" , \"proof\": {\"proof_type\": \"jwt\", \"jwt\": \"%s\"}}", proof);

        requestCredential(mock, (String) token, credentialRequestString)
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
        String credentialRequestString = String.format("{ \"format\": \"vc+sd-jwt\" , \"proof\": {\"proof_type\": \"jwt\", \"jwt\": \"%s\"}}", proof);
        JsonObject credentialResponse = TestInfrastructureUtils.requestFailingCredential(mock, token, credentialRequestString);

        assertEquals(INVALID_PROOF.name(), credentialResponse.get("error").getAsString());
    }

    @Test
    void testHolderBindingProof_GivenIssuedAtWindowInFuture_thenBadRequest() throws Exception {
        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");
        String proof = TestServiceUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), tokenResponse.get("c_nonce").toString(), ProofType.JWT.getClaimTyp(), true, Date.from(Instant.now().plus(1, ChronoUnit.HOURS)));
        String credentialRequestString = String.format("{ \"format\": \"vc+sd-jwt\" , \"proof\": {\"proof_type\": \"jwt\", \"jwt\": \"%s\"}}", proof);
        JsonObject credentialResponse = TestInfrastructureUtils.requestFailingCredential(mock, token, credentialRequestString);

        assertEquals(INVALID_PROOF.name(), credentialResponse.get("error").getAsString());
    }

    @Test
    void testHolderBindingProof_GivenIssuedAtWindowInPast_thenBadRequest() throws Exception {
        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");
        String proof = TestServiceUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), tokenResponse.get("c_nonce").toString(), ProofType.JWT.getClaimTyp(), true, Date.from(Instant.now().minus(1, ChronoUnit.HOURS)));
        String credentialRequestString = String.format("{ \"format\": \"vc+sd-jwt\" , \"proof\": {\"proof_type\": \"jwt\", \"jwt\": \"%s\"}}", proof);
        JsonObject credentialResponse = TestInfrastructureUtils.requestFailingCredential(mock, token, credentialRequestString);

        assertEquals(INVALID_PROOF.name(), credentialResponse.get("error").getAsString());
    }

    @Test
    void testMissingProof_thenBadRequest() throws Exception {
        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");

        String credentialRequestString = "{ \"format\": \"vc+sd-jwt\" , \"proof\": {\"proof_type\": \"jwt\"}}";
        JsonObject credentialResponse = TestInfrastructureUtils.requestFailingCredential(mock, token, credentialRequestString);

        assertEquals("Unprocessable Entity", credentialResponse.get("error_description").getAsString());
    }

    @Test
    void testWithMissingProof_thenBadRequest() throws Exception {
        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");

        String credentialRequestString = "{ \"format\": \"vc+sd-jwt\" }";
        requestCredential(mock, (String) token, credentialRequestString)
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
        var response = mock.perform(post("/oid4vci/api/token")
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

    @Test
    void testCredentialRequestEncryptionEC() throws Exception {

        ECKey ecJWK = new ECKeyGenerator(Curve.P_256)
                .keyID("transportEncKeyEC")
                .generate();

        encryptedCredentialRequestFlow(
                JWEAlgorithm.ECDH_ES,
                EncryptionMethod.A128GCM,
                new ECDHDecrypter(ecJWK.toECPrivateKey()),
                ecJWK.toPublicJWK().toJSONString());
    }

    void encryptedCredentialRequestFlow(JWEAlgorithm alg, EncryptionMethod enc, JWEDecrypter decrypter, String jwkJson) throws Exception {
        var responseEncryptionJson = String.format("""
                {
                    "alg": "%s",
                    "enc": "%s",
                    "jwk": %s
                }
                """, alg.getName(), enc.getName(), jwkJson);

        var jwe = fetchEncryptedCredentialFlow(responseEncryptionJson);
        jwe.decrypt(decrypter);
        var credentialResponseJson = jwe.getPayload().toString();
        JsonObject credentialResponse = JsonParser.parseString(
                        credentialResponseJson)
                .getAsJsonObject();
        String vc = credentialResponse.get("credential").getAsString();

        TestInfrastructureUtils.verifyVC(sdjwtProperties, vc, getUniversityCredentialSubjectData());
    }

    @Test
    void testSdJwtOffer_thenSuccess() throws Exception {

        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");
        var format = "vc+sd-jwt";
        var credentialRequestString = getCredentialRequestString(tokenResponse, format);

        var response = requestCredential(mock, (String) token, credentialRequestString)
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/json"))
                .andExpect(jsonPath("$.credential").isNotEmpty())
                .andExpect(jsonPath("$.format").value("vc+sd-jwt"))
                .andReturn();

        assertNotNull(response);
        var credentialResponse = JsonParser.parseString(
                        response.getResponse().getContentAsString())
                .getAsJsonObject();
        var sdjwtVc = credentialResponse.get("credential").getAsString();
        var jwt = SignedJWT.parse(sdjwtVc.split("~")[0]);
        var claims = jwt.getPayload().toJSONObject();
        assertTrue(claims.containsKey("cnf"));
        Map<String, Object> cnf = (Map<String, Object>) claims.get("cnf");

        // Todo: Refactor this once wallet migration is finished
        // cnf jwk must contain old and expanded jwk
        var holderbindingJwk = JWK.parse((cnf));
        assertEquals(jwk.toECKey().getX(), holderbindingJwk.toECKey().getX());
        assertEquals(KeyType.EC, holderbindingJwk.getKeyType());

        // test expanded jwk
        assertTrue(cnf.containsKey("jwk"));
        var expandedJWK = JWK.parse((Map<String, Object>) cnf.get("jwk"));
        assertEquals(KeyType.EC, expandedJWK.getKeyType());
        assertEquals(jwk.toECKey().getX(), holderbindingJwk.toECKey().getX());

        var statusListType = (String) ((Map<String, Object>) ((Map<String, Object>) claims.get("status")).get("status_list")).get("type");
        assertEquals("SwissTokenStatusList-1.0", statusListType);
        requestCredential(mock, (String) token, credentialRequestString)
                .andExpect(status().isBadRequest());
    }

    @Test
    void testOfferWrongFormat_thenFailure() throws Exception {
        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");
        var invalidFormat = "ldp_vc";
        var credentialRequestString = getCredentialRequestString(tokenResponse, invalidFormat);

        requestCredential(mock, (String) token, credentialRequestString)
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.detail").value("format: Only vc+sd-jwt format is supported"));
    }

    /**
     * Test for evaluating if vct and vct#integrity is set.
     */
    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void testVcTypeIssuing_thenSuccess(boolean useNewNonce) throws Exception {
        // Get VC where vct#integrity is set. Claim should be there and filled
        var boundVc = SignedJWT.parse(getBoundVc(useNewNonce));
        assertNotNull(boundVc.getJWTClaimsSet().getClaims().get("vct#integrity"));

        // Get VC where vct#integrity is not set. Claim should not exist
        var unboundVc = SignedJWT.parse(getUnboundVc());
        assertNull(unboundVc.getJWTClaimsSet().getClaims().get("vc#integrity"));

    }

    @Test
    void testRefreshToken_thenSuccess() throws Exception {
        // When a token has been successfully fetched with DPoP
        var dpopKey = TestInfrastructureUtils.getDPoPKey();
        var tokenResponse = TestInfrastructureUtils.fetchOAuthTokenDpop(mock, validPreAuthCode.toString(), dpopKey, applicationProperties.getExternalUrl());
        var refreshToken = tokenResponse.get("refresh_token");
        assertNotNull(refreshToken);
        // Refresh the token
        var refreshResponse = mock.perform(post("/oid4vci/api/token")
                        .header("DPoP", TestInfrastructureUtils.createDPoP(mock, "POST", applicationProperties.getExternalUrl() + "/api/token", null, dpopKey))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", refreshToken.toString()))
                .andExpect(status().isOk())
                // Assertions w.r.t. RFC 6749 ("The OAuth 2.0 Authorization Framework")
                // specified at https://datatracker.ietf.org/doc/html/rfc6749#section-5.1
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(jsonPath("$.access_token").isNotEmpty()) // REQUIRED
                .andExpect(jsonPath("$.token_type").isNotEmpty()) // REQUIRED
                .andExpect(jsonPath("$.token_type").value("BEARER"))
                .andReturn();
        var newToken = assertDoesNotThrow(() -> objectMapper.readValue(refreshResponse.getResponse().getContentAsString(), OAuthTokenDto.class));
        assertNotEquals(tokenResponse.get("access_token").toString(), newToken.getAccessToken());
        assertNotEquals(refreshToken.toString(), newToken.getRefreshToken());
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

        String proof = TestServiceUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), nonce, ProofType.JWT.getClaimTyp(), true);
        String credentialRequestString = String.format("{ \"format\": \"vc+sd-jwt\" , \"proof\": {\"proof_type\": \"jwt\", \"jwt\": \"%s\"}}", proof);
        return TestInfrastructureUtils.getCredential(mock, token, credentialRequestString);
    }

    private String getUnboundVc() throws Exception {
        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, unboundPreAuthCode.toString());
        var token = tokenResponse.get("access_token");

        String credentialRequestString = "{ \"format\": \"vc+sd-jwt\" }";

        return TestInfrastructureUtils.getCredential(mock, token, credentialRequestString);
    }

    private String getCredentialRequestString(Map<String, Object> tokenResponse, String format) throws JOSEException {
        String proof = TestServiceUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), tokenResponse.get("c_nonce").toString(), ProofType.JWT.getClaimTyp(), false);
        return String.format("{ \"format\": \"%s\" , \"proof\": {\"proof_type\": \"jwt\", \"jwt\": \"%s\"}}", format, proof);
    }

    @NonNull
    private JWEObject fetchEncryptedCredentialFlow(String responseEncryptionJson) throws Exception {
        var tokenResponse = TestInfrastructureUtils.fetchOAuthToken(mock, validPreAuthCode.toString());
        var token = tokenResponse.get("access_token");

        String proof = TestServiceUtils.createHolderProof(jwk, applicationProperties.getTemplateReplacement().get("external-url"), tokenResponse.get("c_nonce").toString(), ProofType.JWT.getClaimTyp(), true);
        String credentialRequestString = String.format("{ \"format\": \"vc+sd-jwt\" , \"proof\": {\"proof_type\": \"jwt\", \"jwt\": \"%s\"}, \"credential_response_encryption\": %s}", proof, responseEncryptionJson);
        var response = requestCredential(mock, (String) token, credentialRequestString)
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/jwt"))
                .andReturn();

        return JWEObject.parse(response.getResponse().getContentAsString());
    }

    private void saveStatusListLinkedOffer(CredentialOffer offer, StatusList statusList, int index) {
        credentialOfferRepository.save(offer);
        credentialOfferStatusRepository.save(linkStatusList(offer, statusList, index));
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