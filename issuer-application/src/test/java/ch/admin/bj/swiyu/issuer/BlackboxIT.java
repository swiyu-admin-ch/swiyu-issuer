package ch.admin.bj.swiyu.issuer;


import ch.admin.bj.swiyu.core.status.registry.client.api.StatusBusinessApiApi;
import ch.admin.bj.swiyu.core.status.registry.client.invoker.ApiClient;
import ch.admin.bj.swiyu.core.status.registry.client.model.StatusListEntryCreationDto;
import ch.admin.bj.swiyu.issuer.api.credentialoffer.CreateCredentialRequestDto;
import ch.admin.bj.swiyu.issuer.api.credentialoffer.CredentialWithDeeplinkResponseDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialResponseEncryptionDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.NonceResponseDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.OAuthTokenDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.OpenIdConfigurationDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2.CredentialEndpointRequestDtoV2;
import ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2.CredentialEndpointResponseDtoV2;
import ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2.CredentialObjectDtoV2;
import ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2.ProofsDto;
import ch.admin.bj.swiyu.issuer.api.statuslist.StatusListDto;
import ch.admin.bj.swiyu.issuer.api.statuslist.StatusListTypeDto;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.management.infrastructure.web.controller.StatusListTestHelper;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.dockerjava.zerodep.shaded.org.apache.hc.core5.net.URLEncodedUtils;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.shaded.org.checkerframework.common.value.qual.IntRange;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests taking the whole application as blackbox, emulating partially a business issuer and a wallet
 */
@SpringBootTest()
@Nested
@DisplayName("Blackbox Test")
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
class BlackboxIT {
    private static final String CREDENTIAL_MANAGEMENT_BASE_URL = "/management/api/credentials";
    protected StatusListTestHelper statusListTestHelper;
    @Autowired
    protected SwiyuProperties swiyuProperties;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private MockMvc mvc;
    @MockitoBean
    private StatusBusinessApiApi statusBusinessApi;
    @Mock
    private ApiClient mockApiClient;

    @BeforeEach
    void setUp() {
        statusListTestHelper = new StatusListTestHelper(mvc, objectMapper);
        final StatusListEntryCreationDto statusListEntry = statusListTestHelper.buildStatusListEntry();
        when(statusBusinessApi.createStatusListEntry(swiyuProperties.businessPartnerId())).thenReturn(statusListEntry);
        when(statusBusinessApi.getApiClient()).thenReturn(mockApiClient);
        when(mockApiClient.getBasePath()).thenReturn(statusListEntry.getStatusRegistryUrl());
    }

    /**
     * Test for when everything goes well, from initializing the status list and creating offers up to receiving the VC
     * For details see <a href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-pre-authorized-code-flow">OID4VCI 1.0 Spec</a>
     */
    @Test
    void preauthorizedCodeFlow_thenSuccess() {
        // ---------------------
        // -- Business Issuer --
        // ---------------------
        // First we have to create a status list
        final StatusListDto statusListDto = assertDoesNotThrow(() -> statusListTestHelper.createStatusList(
                StatusListTypeDto.TOKEN_STATUS_LIST,
                1000,
                // Space for 1000 entries; length / batch size is how many VCs we can store in the status list
                null,
                2,
                // 2 Bits for having the states issue, revoke and suspend (and one unused state)
                null,
                null,
                null,
                null));
        // We will need the status list uri as identifier to indicate which status list will be used a VC we create
        var statusListUri = statusListDto.getStatusRegistryUrl();

        // Now that we have a status list we can create credential offers to issue VCs
        var createRequestBody = assertDoesNotThrow(() -> objectMapper.writeValueAsString(CreateCredentialRequestDto.builder()
                // Select the entry from issuer metadata (in this test case the example_issuer_metadata.json)
                .metadataCredentialSupportedId(List.of("university_example_sd_jwt"))
                // The credential subject data must be matching the claims we publicize that we will issue
                .credentialSubjectData(Map.of("type", "Bachelor", "name", "Bachelor of Science"))
                .statusLists(List.of(statusListUri))
                .build()));

        MvcResult createCredentialOfferResult = assertDoesNotThrow(() -> mvc.perform(post(CREDENTIAL_MANAGEMENT_BASE_URL).contentType(
                                MediaType.APPLICATION_JSON)
                        .content(createRequestBody))
                .andExpect(status().isOk())
                .andReturn());
        var createCredentialOfferResponse = assertDoesNotThrow(() -> objectMapper.readValue(createCredentialOfferResult.getResponse()
                .getContentAsString(), CredentialWithDeeplinkResponseDto.class));
        var deeplink = createCredentialOfferResponse.getOfferDeeplink();
        assertThat(deeplink).as("Deep link is required by the wallet.")
                .isNotBlank()
                .as("A pre-authorized code is used to authenticate and identify the wallet's call")
                .contains("pre-authorized_code");
        // The management ID is used by the business issuer to set status and re-identify the offer in callbacks
        var vcManagementId = createCredentialOfferResponse.getManagementId();
        assertThat(vcManagementId).as("Management Id is used to reidentify the VC in future calls")
                .isNotNull();

        // We can now pass the deeplink in some form to the wallet. This could be via QR-Code or even an SMS

        // ------------
        // -- Wallet --
        // ------------
        // The deeplink the wallet receives is url encoded
        // Example:
        // swiyu://?credential_offer=%7B%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%224856e65a-775d-4356-bf47-cb9920f64495%22%7D%7D%2C%22version%22%3A%221.0%22%2C%22credential_issuer%22%3A%22http%3A%2F%2Flocalhost%3A8080%2Ftest%2F%22%2C%22credential_configuration_ids%22%3A%5B%22university_example_sd_jwt%22%5D%7D
        var parsedDeeplink = assertDoesNotThrow(() -> new URI(deeplink));
        assertThat(parsedDeeplink.getScheme()).as("The swiyu wallet expects the deeplink to have the correct scheme")
                .isEqualTo("swiyu");
        var offerQuery = URLEncodedUtils.parse(parsedDeeplink, StandardCharsets.UTF_8);
        var credentialOffer = offerQuery.get(0);
        assertThat(credentialOffer.getName()).as("Offer has the value credential_offer")
                .isEqualTo("credential_offer");

        // For more details what to see in the offer see 4.1.1 Credential Offer Parameters
        // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1.1
        var parsedOffer = assertDoesNotThrow(
                () -> objectMapper.readValue(credentialOffer.getValue(), Map.class));

        // We have the grant offer type
        assertThat((Map<String, Object>) parsedOffer.get("grants")).containsKey(
                "urn:ietf:params:oauth:grant-type:pre-authorized_code");
        var preAuthCode = assertDoesNotThrow(() -> ((Map) ((Map) parsedOffer.get("grants")).get(
                "urn:ietf:params:oauth:grant-type:pre-authorized_code")).get("pre-authorized_code")).toString();
        assertThat(preAuthCode).isNotBlank();
        // We can also see what the issuer is offering us
        var offeredCredentialIds = assertDoesNotThrow(() -> ((List<String>) parsedOffer.get(
                "credential_configuration_ids")));

        var issuerUri = assertDoesNotThrow(() -> new URI(parsedOffer.get("credential_issuer")
                        .toString()
                        .replaceAll("/+$", "")),
                "The wallet will need the credential_issuer as base URL for all the well known calls");
        var baseIssuerUri = issuerUri.toString()
                .replace(issuerUri.getPath(), "");

        // Next the wallet wants to fetch the well-known endpoints
        var openidConfigResponse = assertDoesNotThrow(() -> mvc.perform(get(
                        "/oid4vci/.well-known/oauth-authorization-server"))
                .andExpect(status().isOk())
                .andReturn());
        var oauthConfig = assertDoesNotThrow(() -> objectMapper.readValue(openidConfigResponse.getResponse()
                        .getContentAsString(),
                OpenIdConfigurationDto.class));
        assertThat(oauthConfig.issuer()).isEqualTo(baseIssuerUri);

        var issuerMetadataResponse = assertDoesNotThrow(() -> mvc.perform(get(
                        "/oid4vci/.well-known/openid-credential-issuer"))
                .andExpect(status().isOk())
                .andReturn());

        var issuerMetadata = assertDoesNotThrow(() -> objectMapper.readValue(issuerMetadataResponse.getResponse()
                        .getContentAsString(),
                IssuerMetadata.class));

        assertThat(issuerMetadata.getCredentialConfigurationSupported()
                .keySet())
                .as("The issuer must declare in its metadata that is offers the credential type offered")
                .containsAll(offeredCredentialIds);
        assertThat(issuerMetadata.getCredentialIssuer()).isEqualTo(baseIssuerUri);

        // TODO EIDOMNI-200 validate metadata signature

        // Fetch the bearer token
        // TODO EIDOMNI-274 add DPoP process

        var tokenResponse = assertDoesNotThrow(() -> mvc.perform(post(oauthConfig.token_endpoint()
                                .replace(baseIssuerUri, ""))
                                .param("grant_type", "urn:ietf:params:oauth:grant-type:pre-authorized_code")
                                .param("pre-authorized_code", preAuthCode))
                        .andExpect(status().isOk())
                        .andReturn(),
                "Should be able to successfully request token using token endpoint from well-known uri"
        );
        var oauthTokenResponse = assertDoesNotThrow(() -> objectMapper.readValue(tokenResponse.getResponse()
                .getContentAsString(), OAuthTokenDto.class));
        assertThat(oauthTokenResponse.getAccessToken()).isNotBlank();


        // TODO Currently we only support a single VC type, this should be expanded
        var offeredVCConfiguration = issuerMetadata.getCredentialConfigurationById(offeredCredentialIds.getFirst());
        var proofTypes = offeredVCConfiguration.getProofTypesSupported();
        assertThat(proofTypes)
                .as("proof_types_supported indicates if the wallest must send holder binding proofs (and the VC being bound to a private key owned by the wallet)")
                .isNotNull()
                .containsKey("jwt");
        assertThat(issuerMetadata.getNonceEndpoint()).isNotBlank();


        // To create the holder binding proof we need a key pair
        var holderBindingKeys = IntStream.range(0, issuerMetadata.getIssuanceBatchSize())
                .boxed()
                .map(i -> assertDoesNotThrow(() -> new ECKeyGenerator(Curve.P_256).keyID("HolderBindingKey#%s".formatted(
                                i))
                        .keyUse(KeyUse.SIGNATURE)
                        .generate()))
                .toList();
        var holderEncryptionKeys = assertDoesNotThrow(() -> new ECKeyGenerator(Curve.P_256).keyID("HolderEncryptionKey")
                .keyUse(KeyUse.ENCRYPTION)
                .generate());

        var holderBindingJwts = holderBindingKeys.stream()
                .map(holderBindingKey -> createHolderBindingJwt(holderBindingKey, baseIssuerUri, issuerMetadata))
                .map(SignedJWT::serialize)
                .toList();

        var credentialRequestDto = new CredentialEndpointRequestDtoV2(
                offeredCredentialIds.getFirst(),
                new ProofsDto(holderBindingJwts),
                new CredentialResponseEncryptionDto(
                        holderEncryptionKeys.toPublicJWK()
                                .toJSONObject(),
                        issuerMetadata.getResponseEncryption()
                                .getAlgValuesSupported()
                                .getFirst(),
                        issuerMetadata.getResponseEncryption()
                                .getEncValuesSupported()
                                .getFirst()
                )
        );
        var requestEncryption = issuerMetadata.getRequestEncryption();
        assertThat(requestEncryption).as("Credential Request Encryption to protect holder binding proofs")
                .isNotNull();
        assertThat(requestEncryption.getJwks()).isNotEmpty();
        assertThat(requestEncryption.getEncValuesSupported()).isNotEmpty()
                .contains(EncryptionMethod.A128GCM.getName());
        var requestJwks = assertDoesNotThrow(() -> JWKSet.parse(requestEncryption.getJwks()));
        // Currently we only support a single EC key, so we can cheat here
        var issuerEncryptionKey = requestJwks.getKeys()
                .getFirst();
        var encryptedCredentialRequest = assertDoesNotThrow(() -> new EncryptedJWT(new JWEHeader.Builder(JWEAlgorithm.ECDH_ES,
                EncryptionMethod.A128GCM).keyID(issuerEncryptionKey.getKeyID())
                .compressionAlgorithm(CompressionAlgorithm.DEF)
                .build(),
                JWTClaimsSet.parse(objectMapper.writeValueAsString(credentialRequestDto))));
        assertDoesNotThrow(() -> encryptedCredentialRequest.encrypt(new ECDHEncrypter(issuerEncryptionKey.toECKey())));

        // Request the Credential with an encrypted credential request
        var credentialResponse = assertDoesNotThrow(() -> mvc.perform(post(issuerMetadata.getCredentialEndpoint()
                        .replace(baseIssuerUri, ""))
                        .header("Authorization", "bearer " + oauthTokenResponse.getAccessToken())
                        .header("SWIYU-API-Version", "2")
                        .contentType("application/jwt") // Content Type for encrypted request
                        .content(encryptedCredentialRequest.serialize())
                )
                .andExpect(status().isOk())
                .andReturn());
        assertThat(credentialResponse.getResponse()
                .getContentType()).as(
                        "The contents of the message MUST be encoded as a JWT as described in [RFC7519]. The media type MUST be set to application/jwt.")
                .isEqualTo("application/jwt");
        var credentialResponseJwt = assertDoesNotThrow(() -> EncryptedJWT.parse(credentialResponse.getResponse()
                .getContentAsString()));
        assertDoesNotThrow(() -> credentialResponseJwt.decrypt(new ECDHDecrypter(holderEncryptionKeys.toECKey())));
        var credentialResponseDto = assertDoesNotThrow(() -> objectMapper.readValue(credentialResponseJwt.getJWTClaimsSet()
                        .toString(),
                CredentialEndpointResponseDtoV2.class));
        assertThat(credentialResponseDto.credentials()).as(
                        "The flow is not deferred, the credentials should be directly returned")
                .hasSize(issuerMetadata.getIssuanceBatchSize());
        assertThat(credentialResponseDto.interval()).isNull();
        assertThat(credentialResponseDto.transactionId()).isNull();
        var verifiableCredentialClaims = credentialResponseDto.credentials()
                .stream()
                .map(CredentialObjectDtoV2::credential)
                .map(rawSdJwt -> rawSdJwt.split("~")[0])
                .map(rawJwt -> assertDoesNotThrow(() -> SignedJWT.parse(rawJwt)))
                .map(signedJwt -> assertDoesNotThrow(signedJwt::getJWTClaimsSet))
                .toList();
        var statusIndexes = verifiableCredentialClaims.stream()
                .map(claimSet -> (Map<String, Map<String, Object>>) claimSet.getClaim("status"))
                .map(statusToken -> statusToken.get("status_list")
                        .get("idx")
                        .toString())
                .distinct()
                .toList();
        assertThat(statusIndexes).hasSize(issuerMetadata.getIssuanceBatchSize());


    }

    @NotNull
    private SignedJWT createHolderBindingJwt(ECKey holderBindingKey,
                                             String baseIssuerUri,
                                             IssuerMetadata issuerMetadata) {
        // We need a fresh nonce for the holder binding proofs
        var nonceResponse = assertDoesNotThrow(() -> mvc.perform(post(issuerMetadata.getNonceEndpoint()
                                .replace(baseIssuerUri, "")))
                        .andExpect(status().isOk())
                        .andReturn(),
                "Should be able to successfully request token using token endpoint from well-known uri"
        );
        // Note: This is a self-contained nonce and therefore has an expiry date
        var nonce = assertDoesNotThrow(() -> objectMapper.readValue(nonceResponse.getResponse()
                .getContentAsString(), NonceResponseDto.class))
                .nonce();
        // For more details about proofs see
        // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-F.1
        var holderBindingJwt = new SignedJWT(
                new JWSHeader.Builder(
                        JWSAlgorithm.ES256)
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
                "Singing the wallet holder binding proof with the wallet key");
        return holderBindingJwt;
    }
}
