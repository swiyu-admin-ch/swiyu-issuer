package ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.common.config.SignatureConfiguration;
import ch.admin.bj.swiyu.issuer.common.profile.SwissProfileVersions;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialManagementRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusListRepository;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.dto.common.ConfigurationOverrideDto;
import ch.admin.bj.swiyu.issuer.dto.credentialoffer.CreateCredentialOfferRequestDto;
import ch.admin.bj.swiyu.issuer.dto.credentialoffer.CredentialWithDeeplinkResponseDto;
import ch.admin.bj.swiyu.issuer.management.infrastructure.web.controller.CredentialOfferTestHelper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import org.apache.http.client.utils.URLEncodedUtils;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.junit.jupiter.Testcontainers;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.stream.IntStream;

import static ch.admin.bj.swiyu.issuer.oid4vci.test.TestInfrastructureUtils.createPemForKid;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles({"test", "signed-metadata"})
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
@Transactional
class WellKnownControllerIT {
    protected CredentialOfferTestHelper testHelper;
    @Autowired
    private MockMvc mock;
    @Autowired
    private ObjectMapper objectMapper;
    @MockitoSpyBean
    private SdjwtProperties sdjwtProperties;
    @Autowired
    private CredentialOfferRepository credentialOfferRepository;
    @Autowired
    private StatusListRepository statusListRepository;
    @Autowired
    private CredentialOfferStatusRepository credentialOfferStatusRepository;
    @Autowired
    private CredentialManagementRepository credentialManagementRepository;

    @BeforeEach
    void setupTest() {
        var statusRegistryUUID = UUID.randomUUID();
        var statusRegistryUrl = "https://status-service-mock.bit.admin.ch/api/v1/statuslist/%s.jwt"
                .formatted(statusRegistryUUID);
        testHelper = new CredentialOfferTestHelper(mock, credentialOfferRepository, credentialOfferStatusRepository, statusListRepository, credentialManagementRepository,
                statusRegistryUrl);
    }

    @Test
    void testGetAuthorizationServerMetadata_thenSuccess() throws Exception {
        mock.perform(get("/oid4vci/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("token_endpoint")))
                .andExpect(content().string(containsString("\"pre-authorized_grant_anonymous_access_supported\":true")))
                .andExpect(content().string(not(containsString("${external-url}"))));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/.well-known/oauth-authorization-server",
            "/oid4vci/.well-known/oauth-authorization-server",
            "/.well-known/oauth-authorization-server/oid4vci"})
    void testGetOauthAuthorizationServer_thenSuccess(String uri) throws Exception {
        mock.perform(get(uri))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("token_endpoint")))
                .andExpect(content().string(containsString("\"pre-authorized_grant_anonymous_access_supported\":true")))
                .andExpect(content().string(not(containsString("${external-url}"))));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "/.well-known/openid-credential-issuer",
            "/oid4vci/.well-known/openid-credential-issuer",
            "/.well-known/openid-credential-issuer/oid4vci"})
    void testGetIssuerMetadata_thenSuccess(String uri) throws Exception {
        mock.perform(get(uri).accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.profile_version").value(SwissProfileVersions.ISSUANCE_PROFILE_VERSION))
                .andExpect(content().string(not(containsString("${external-url}"))))
                .andExpect(content().string(containsString("credential_endpoint")))
                .andExpect(content().string(not(containsString("${stage}")))) // stage placeholder should be replace
                .andExpect(content().string(containsString("local-Example Credential"))) // Replaced placeholder examples
                .andExpect(content().string(containsString("local-university_example_sd_jwt")))
                .andExpect(content().string(containsString("\"vct_metadata_uri\""))) // vct metadata indirection should not be filtered out if used
                .andExpect(content().string(containsString("\"vct_metadata_uri#integrity\""))) // integrity for vct metadata indirection should not be filtered out if used
                .andExpect(content().string(Matchers.not(containsString("issuanceBatchSize")))); // Util Field should not be displayed metadata
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "%s/.well-known/openid-credential-issuer",
            "/oid4vci/%s/.well-known/openid-credential-issuer",
            "/.well-known/openid-credential-issuer/%s",
            "/.well-known/openid-credential-issuer/oid4vci/%s",
    })
    void testGetIssuerMetadataByTenantIdSigned_thenSuccess(String uri) throws Exception {
        var tenantId = testHelper.createBasicOfferJsonAndGetTenantID();

        var response = assertDoesNotThrow(() -> mock.perform(get(
                        uri.formatted(tenantId))
                        .accept("application/JWT,application/JSON"))
                .andExpect(status().isOk())
                .andReturn());

        var issuerMetadataJwt = assertDoesNotThrow(() -> SignedJWT.parse(response.getResponse()
                .getContentAsString()), "Well Known data should be a parsable JWT");
        var header = issuerMetadataJwt.getHeader();

        assertEquals("openidvci-issuer-metadata+jwt", header.getType().getType());
        assertEquals("ES256", header.getAlgorithm().getName());
        assertEquals(SwissProfileVersions.ISSUANCE_PROFILE_VERSION, header.getCustomParam(SwissProfileVersions.PROFILE_VERSION_PARAM));
    }


    @Test
    void testGetIssuerMetadata_withOverride_andIncorrectkey_byTenantIdSigned_thenSuccess() throws Exception {
        var issuerDid = "did:example:override";
        var issuerKid = issuerDid + "#key-1";

        CreateCredentialOfferRequestDto credentialOfferDto = CreateCredentialOfferRequestDto.builder()
                .metadataCredentialSupportedId(java.util.List.of("test"))
                .credentialSubjectData(java.util.Map.of("firstName", "firstName", "lastName", "lastName", "dateOfBirth", "1990-01-01"))
                .configurationOverride(new ConfigurationOverrideDto(issuerDid, issuerKid, null, null))
                .build();

        String payloadString = objectMapper.writeValueAsString(credentialOfferDto);

        var offer = testHelper.createOffer(payloadString).andExpect(status().isOk());

        var createCredentialOfferResponse = assertDoesNotThrow(() -> objectMapper.readValue(offer.andReturn().getResponse()
                .getContentAsString(), CredentialWithDeeplinkResponseDto.class));
        var deeplink = createCredentialOfferResponse.getOfferDeeplink();
        var parsedDeeplink = assertDoesNotThrow(() -> new URI(deeplink));
        var offerQuery = URLEncodedUtils.parse(parsedDeeplink, StandardCharsets.UTF_8);
        var credentialOffer = offerQuery.getFirst();
        JsonNode node = assertDoesNotThrow(() -> objectMapper.readTree(credentialOffer.getValue()));
        var tenantId = node.get("credential_issuer").asString().split("http://localhost:8080")[1];

        mock.perform(get("%s/.well-known/openid-credential-issuer".formatted(tenantId))
                        .accept("application/jwt, application/json"))
                .andExpect(status().isInternalServerError());
    }

    @ParameterizedTest
    @ValueSource(strings = {"did:example:localhost%3A8080:abcabc#sdjwt", "did:example:override#key-0", "did:example:override#key-1", "did:example:override#key-2"})
    void testGetIssuerMetadata_withOverride_byTenantIdSigned_thenSuccess(String expectedKid) throws Exception {

        var overrideDID = "did:example:override";
        var verificationMethod = overrideDID + "#key";
        var signingKeys = IntStream.range(0, 3)
                .mapToObj(i -> {
                    var keyId = verificationMethod + "-" + i;
                    String pemKey;
                    try {
                        pemKey = createPemForKid(keyId);
                    } catch (JOSEException e) {
                        throw new RuntimeException(e);
                    }
                    SignatureConfiguration signatureConfiguration = new SignatureConfiguration();
                    signatureConfiguration.setKeyManagementMethod("key");
                    signatureConfiguration.setPrivateKey(pemKey);
                    signatureConfiguration.setVerificationMethod(keyId);
                    return signatureConfiguration;
                })
                .toList();

        when(sdjwtProperties.getSigningKeys()).thenReturn(signingKeys);
        when(sdjwtProperties.supportsSigningKeys()).thenReturn(true);

        CreateCredentialOfferRequestDto credentialOfferDto = CreateCredentialOfferRequestDto.builder()
                .metadataCredentialSupportedId(java.util.List.of("test"))
                .credentialSubjectData(java.util.Map.of("firstName", "firstName", "lastName", "lastName", "dateOfBirth", "1990-01-01"))
                .configurationOverride(new ConfigurationOverrideDto(overrideDID, expectedKid, null, null))
                .build();

        String payloadString = objectMapper.writeValueAsString(credentialOfferDto);

        var offer = testHelper.createOffer(payloadString).andExpect(status().isOk());

        var createCredentialOfferResponse = assertDoesNotThrow(() -> objectMapper.readValue(offer.andReturn().getResponse()
                .getContentAsString(), CredentialWithDeeplinkResponseDto.class));
        var deeplink = createCredentialOfferResponse.getOfferDeeplink();
        var parsedDeeplink = assertDoesNotThrow(() -> new URI(deeplink));
        var offerQuery = URLEncodedUtils.parse(parsedDeeplink, StandardCharsets.UTF_8);
        var credentialOffer = offerQuery.getFirst();
        JsonNode node = assertDoesNotThrow(() -> objectMapper.readTree(credentialOffer.getValue()));
        var tenantId = node.get("credential_issuer").asString().split("http://localhost:8080")[1];

        var response = assertDoesNotThrow(() -> mock.perform(get(
                        "%s/.well-known/openid-credential-issuer".formatted(tenantId))
                        .accept("application/JWT,application/JSON"))
                .andExpect(status().isOk())
                .andReturn());

        JWT jwt = JWTParser.parse(response.getResponse().getContentAsString());

        var header = jwt.getHeader();
        assertEquals(expectedKid, ((JWSHeader) header).getKeyID());

        // check payload details
        var claimsSet = jwt.getJWTClaimsSet();
        assertEquals(overrideDID, claimsSet.getIssuer());
    }


    @ParameterizedTest
    @ValueSource(strings = {
            "%s/.well-known/openid-credential-issuer",
            "/oid4vci/%s/.well-known/openid-credential-issuer",
            "/.well-known/openid-credential-issuer/%s",
            "/.well-known/openid-credential-issuer/oid4vci/%s",
    })
    void testGetIssuerMetadataByTenantIdUnsigned_thenSuccess() throws Exception {
        var url = testHelper.createBasicOfferJsonAndGetTenantID();

        mock.perform(get("%s/.well-known/openid-credential-issuer".formatted(url))
                        .accept("Application/json,application/jwt;q=0.0"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.profile_version").value(SwissProfileVersions.ISSUANCE_PROFILE_VERSION))
                .andExpect(content().string(not(containsString("${external-url}"))))
                .andExpect(content().string(containsString("credential_endpoint")));
    }


    @Test
    void testGetIssuerMetadataByUnknownTenantIdUnsigned_thenError() throws Exception {
        var url = "0-0-0-0";

        mock.perform(get("/oid4vci/%s/.well-known/openid-credential-issuer".formatted(url))
                        .accept("Application/json,application/jwt;q=0.0"))
                .andExpect(status().isBadRequest());
    }


    @Test
    void testWellknownJwksComplete() {
        assertDoesNotThrow(() -> mock.perform(get("/oid4vci/.well-known/openid-credential-issuer").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.credential_request_encryption.jwks.keys[0].kty").value("EC"))
                .andExpect(jsonPath("$.credential_request_encryption.jwks.keys[0].crv").value("P-256"))
                .andExpect(jsonPath("$.credential_request_encryption.jwks.keys[0].alg").value("ECDH-ES")));
    }

    @Test
    void testGetIssuerSignedMetadataSubject_thenSuccess() throws Exception {
        var url = testHelper.createBasicOfferJsonAndGetTenantID();
        var issuerPublicKey = assertDoesNotThrow(() -> JWK.parseFromPEMEncodedObjects(sdjwtProperties.getPrivateKey()).toECKey().toECPublicKey());
        var issuerSignatureVerifier = assertDoesNotThrow(() -> new ECDSAVerifier(issuerPublicKey));

        // openid-credential-issuer
        var issuerMetadataResponse = assertDoesNotThrow(() -> mock.perform(get(
                        "%s/.well-known/openid-credential-issuer".formatted(url))
                        .accept("Application/jwT;q=0.1,APPLICATION/JSON;q=0.9"))
                .andExpect(status().isOk())
                .andReturn());

        var issuerMetadataJwt = assertDoesNotThrow(() -> SignedJWT.parse(issuerMetadataResponse.getResponse()
                .getContentAsString()), "Well Known data should be a parsable JWT");

        assertDoesNotThrow(() -> issuerMetadataJwt.verify(issuerSignatureVerifier), "Signed Metadata must have a valid signature");
        var issuerMetadata = assertDoesNotThrow(() -> objectMapper.readValue(issuerMetadataJwt.getPayload().toString(),
                IssuerMetadata.class));

        var sub = issuerMetadataJwt.getPayload().toJSONObject().get("sub").toString();
        assertEquals(issuerMetadata.getCredentialIssuer(), sub);

        // openid-configuration
        var metadataResponse = assertDoesNotThrow(() -> mock.perform(get(
                        "%s/.well-known/openid-configuration".formatted(url))
                        .accept("application/jwt"))
                .andExpect(status().isOk())
                .andReturn());

        var metadataJwt = assertDoesNotThrow(() -> SignedJWT.parse(metadataResponse.getResponse()
                .getContentAsString()), "Well Known data should be a parsable JWT");

        assertDoesNotThrow(() -> metadataJwt.verify(issuerSignatureVerifier), "Signed Metadata must have a valid signature");

        sub = metadataJwt.getPayload().toJSONObject().get("sub").toString();
        assertTrue(sub.contains("http://localhost:8080"));
    }

    @Test
    void testGetIssuerMetadata_PreferSigned() throws Exception {
        var issuerPublicKey = assertDoesNotThrow(() -> JWK.parseFromPEMEncodedObjects(sdjwtProperties.getPrivateKey()).toECKey().toECPublicKey());
        var issuerSignatureVerifier = assertDoesNotThrow(() -> new ECDSAVerifier(issuerPublicKey));

        // when json and jwt are allowed, prefer jwt
        var url = testHelper.createBasicOfferJsonAndGetTenantID();
        var issuerMetadataResponse = assertDoesNotThrow(() -> mock.perform(get(
                        "%s/.well-known/openid-credential-issuer".formatted(url))
                        .accept("application/json,application/jwt"))
                .andExpect(status().isOk())
                .andReturn());

        var issuerMetadataJwt = assertDoesNotThrow(() -> SignedJWT.parse(issuerMetadataResponse.getResponse()
                .getContentAsString()), "Well Known data should be a parsable JWT");
        assertDoesNotThrow(() -> issuerMetadataJwt.verify(issuerSignatureVerifier), "Signed Metadata must have a valid signature");

        var metadataResponse = assertDoesNotThrow(() -> mock.perform(get(
                        "%s/.well-known/openid-configuration".formatted(url))
                        .accept("application/json,application/jwt"))
                .andExpect(status().isOk())
                .andReturn());

        var metadataJwt = assertDoesNotThrow(() -> SignedJWT.parse(metadataResponse.getResponse()
                .getContentAsString()), "Well Known data should be a parsable JWT");
        assertDoesNotThrow(() -> metadataJwt.verify(issuerSignatureVerifier), "Signed Metadata must have a valid signature");
    }

}