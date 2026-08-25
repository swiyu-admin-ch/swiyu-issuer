package ch.admin.bj.swiyu.issuer.management.infrastructure.web.controller;

import ch.admin.bj.swiyu.core.status.registry.client.api.StatusBusinessApiApi;
import ch.admin.bj.swiyu.core.status.registry.client.invoker.ApiClient;
import ch.admin.bj.swiyu.core.status.registry.client.model.StatusListEntryCreationDto;
import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.common.config.*;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusList;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusListRepository;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.dto.credentialofferstatus.CredentialStatusTypeDto;
import ch.admin.bj.swiyu.issuer.service.JwsSignatureFacade;
import ch.admin.bj.swiyu.issuer.service.statusregistry.StatusRegistryClient;
import ch.admin.bj.swiyu.jwssignatureservice.factory.strategy.KeyStrategyException;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import org.apache.commons.lang3.RandomStringUtils;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.junit.jupiter.Testcontainers;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.IntStream;

import static ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller.IssuanceTestUtils.*;
import static ch.admin.bj.swiyu.issuer.oid4vci.test.CredentialOfferTestData.getMinimalPayloadForCredentialSupportedIdTest;
import static ch.admin.bj.swiyu.issuer.oid4vci.test.CredentialOfferTestData.getMinimalPayloadForUniversityCredential;
import static ch.admin.bj.swiyu.issuer.oid4vci.test.TestInfrastructureUtils.createPemForKid;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest()
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
class StatusListIT {

    public static final String STATUS_LIST_BASE_URL = "/management/api/status-list";
    private static final String BASE_URL = "/management/api/credentials";
    private final UUID statusListUUID = UUID.randomUUID();
    private final String statusRegistryUrl = "https://status-service-mock.bit.admin.ch/api/v1/statuslist/%s.jwt"
            .formatted(statusListUUID);
    private final String overrideDID = "did:example:offer:override";
    private final ApiClient mockApiClient = Mockito.mock(ApiClient.class);
    @Autowired
    private SwiyuProperties swiyuProperties;
    @Autowired
    private MockMvc mvc;
    @MockitoSpyBean
    private StatusListProperties statusListProperties;
    @Autowired
    private StatusListRepository statusListRepository;
    @MockitoBean
    private StatusBusinessApiApi statusBusinessApi;
    @MockitoSpyBean
    private JwsSignatureFacade jwsSignatureFacade;
    @Autowired
    private IssuerMetadata issuerMetadata;
    @MockitoSpyBean
    private ApplicationProperties applicationProperties;
    @MockitoSpyBean
    private StatusRegistryClient statusRegistryClient;

    @BeforeEach
    void setUp() throws JOSEException, KeyStrategyException {
        // Reset the spy so that stubs (e.g. isAutomaticStatusListSynchronizationDisabled=true) from
        // previous tests do not bleed into tests that expect the real/default behaviour.
        Mockito.reset(applicationProperties);

        var statusListEntryCreationDto = new StatusListEntryCreationDto();
        statusListEntryCreationDto.setId(statusListUUID);
        statusListEntryCreationDto.setStatusRegistryUrl(statusRegistryUrl);

        when(statusBusinessApi.createStatusListEntry(swiyuProperties.businessPartnerId()))
                .thenReturn(Mono.just(statusListEntryCreationDto));
        when(statusBusinessApi.updateStatusListEntry(any(), any(), any())).thenReturn(Mono.empty());
        when(statusBusinessApi.getApiClient()).thenReturn(mockApiClient);
        when(mockApiClient.getBasePath()).thenReturn(statusRegistryUrl);

        final JWSSigner es256Signer = new ECDSASigner(new ECKeyGenerator(Curve.P_256).keyID("test-key").generate());
    }

    @Test
    void createNewStatusList_thenSuccess() throws Exception {
        JsonObject statusList = createStatusList();

        final Optional<StatusList> newStatusListOpt = statusListRepository.findById(UUID.fromString(statusList.get("id").getAsString()));
        assertTrue(newStatusListOpt.isPresent());
        final StatusList newStatusList = newStatusListOpt.get();
        assertNotNull(newStatusList.getUri());
        assertNull(newStatusList.getConfigurationOverride().issuerDid());
        assertNull(newStatusList.getConfigurationOverride().verificationMethod());
        assertNull(newStatusList.getConfigurationOverride().keyId());
        assertNull(newStatusList.getConfigurationOverride().keyPin());
    }

    private @NotNull JsonObject createStatusList() throws Exception {
        var type = "TOKEN_STATUS_LIST";
        var maxLength = 255;
        var bits = 2;
        var payload = String.format("{\"type\": \"%s\",\"maxLength\": %d,\"config\": {\"bits\": %d}}", type, maxLength,
                bits);

        var result = mvc.perform(post(STATUS_LIST_BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").isNotEmpty())
                .andExpect(jsonPath("$.statusRegistryUrl").isNotEmpty())
                .andExpect(jsonPath("$.maxListEntries").value(maxLength))
                .andExpect(jsonPath("$.remainingListEntries").value(maxLength))
                .andExpect(jsonPath("$.config.bits").value(bits))
                .andReturn().getResponse()
                .getContentAsString();

        return JsonParser.parseString(result).getAsJsonObject();
    }

    @Test
    void createNewStatusListOverrideConfiguration_thenSuccess() throws Exception {

        final int maxLength = 127;
        final int bits = 4;
        final String did = "did:tdw:example";
        final String verificationMethod = did + "#12345";
        final String keyId = "1052933";
        final String keyPin = "209323";
        final String payload = String.format(
                "{\"maxLength\": %d,\"config\": {\"bits\": %d},\"configuration_override\": {\"issuer_did\": \"%s\",\"verification_method\": \"%s\",\"key_id\": %s,\"key_pin\": %s}}", maxLength, bits, did, verificationMethod, keyId, keyPin);

        var hsmConfig = getHsmProperties(keyId);
        when(statusListProperties.getHsm()).thenReturn(hsmConfig);

        MvcResult result = mvc.perform(post(STATUS_LIST_BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isOk())
                .andReturn();

        final UUID newStatusListId = UUID.fromString(JsonPath.read(result.getResponse().getContentAsString(), "$.id"));

        final Optional<StatusList> newStatusListOpt = statusListRepository.findById(newStatusListId);
        assertTrue(newStatusListOpt.isPresent());
        final StatusList newStatusList = newStatusListOpt.get();
        assertNotNull(newStatusList.getUri());
        assertEquals(maxLength, newStatusList.getMaxLength());
        assertEquals(bits, newStatusList.getConfig().get("bits"));
        assertEquals(did, newStatusList.getConfigurationOverride().issuerDid());
        assertEquals(verificationMethod, newStatusList.getConfigurationOverride().verificationMethod());
        assertEquals(keyId, newStatusList.getConfigurationOverride().keyId());
        assertEquals(keyPin, newStatusList.getConfigurationOverride().keyPin());

        verify(jwsSignatureFacade, atLeastOnce()).createSigner(
                statusListProperties,
                newStatusList.getConfigurationOverride()
        );
    }

    @Test
    void createNewStatusList_withIncorrectSigningKeysOverride_thenBadRequest() throws Exception {

        var kid = "did:example:offer:override#key-other";
        var pem = createPemForKid(kid);

        SignatureConfiguration signatureConfiguration = new SignatureConfiguration();
        signatureConfiguration.setKeyManagementMethod("key");
        signatureConfiguration.setPrivateKey(pem);
        signatureConfiguration.setVerificationMethod(kid);

        when(statusListProperties.getSigningKeys()).thenReturn(List.of(signatureConfiguration));
        when(statusListProperties.supportsSigningKeys()).thenReturn(true);

        final int maxLength = 127;
        final int bits = 4;
        final String verificationMethod = overrideDID + "#key";
        final String payload = String.format(
                "{\"maxLength\": %d,\"config\": {\"bits\": %d},\"configuration_override\": {\"issuer_did\": \"%s\",\"verification_method\": \"%s\",\"key_id\": null,\"key_pin\": null}}", maxLength, bits, overrideDID, verificationMethod);

        mvc.perform(post(STATUS_LIST_BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                // todo check if correct status code
                .andExpect(status().isInternalServerError())
                .andReturn();
    }

    @ParameterizedTest
    @ValueSource(strings = {"did:tdw:example#12345", "did:example:offer:override#key-0", "did:example:offer:override#key-1", "did:example:offer:override#key-2"})
    void createNewStatusList_withSigningKeysOverride_thenSuccess(String expectedKid) throws Exception {
        final String verificationMethod = overrideDID + "#key";
        var signingKeys = IntStream.range(0, 3)
                .mapToObj(i -> {
                    var keyId = verificationMethod + "-" + i;
                    String pemKey = null;
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

        when(statusListProperties.getSigningKeys()).thenReturn(signingKeys);
        when(statusListProperties.supportsSigningKeys()).thenReturn(true);

        final int maxLength = 127;
        final int bits = 4;
        final String payload = String.format(
                "{\"maxLength\": %d,\"config\": {\"bits\": %d},\"configuration_override\": {\"issuer_did\": \"%s\",\"verification_method\": \"%s\",\"key_id\": null,\"key_pin\": null}}", maxLength, bits, overrideDID, expectedKid);

        MvcResult result = mvc.perform(post(STATUS_LIST_BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isOk())
                .andReturn();

        final UUID newStatusListId = UUID.fromString(JsonPath.read(result.getResponse().getContentAsString(), "$.id"));

        final Optional<StatusList> newStatusListOpt = statusListRepository.findById(newStatusListId);
        final StatusList newStatusList = newStatusListOpt.get();
        assertEquals(overrideDID, newStatusList.getConfigurationOverride().issuerDid());
        assertEquals(expectedKid, newStatusList.getConfigurationOverride().verificationMethod());
        assertNull(newStatusList.getConfigurationOverride().keyId());
        assertNull(newStatusList.getConfigurationOverride().keyPin());

        ArgumentCaptor<String> captor =
                ArgumentCaptor.forClass(String.class);

        doNothing().when(statusRegistryClient).updateStatusListEntry(any(), any());
        verify(statusRegistryClient).updateStatusListEntry(any(), captor.capture());

        JWT jwt = JWTParser.parse(captor.getValue());

        var header = jwt.getHeader();

        // check header details
        assertEquals("ES256", header.getAlgorithm().getName());
        assertEquals("statuslist+jwt", header.getType().getType());
        assertEquals(expectedKid, ((JWSHeader) header).getKeyID());
        assertEquals("swiss-profile-vc:1.0.0", header.getCustomParam("profile_version"));

        // check payload details
        var claimsSet = jwt.getJWTClaimsSet();
        assertEquals(overrideDID, claimsSet.getIssuer());
        assertEquals(statusRegistryUrl, claimsSet.getSubject());
        assertNotNull(claimsSet.getExpirationTime());
        assertNotNull(claimsSet.getClaim("ttl"));
        assertNotNull(claimsSet.getClaim("iat"));
        assertNotNull(claimsSet.getClaim("status_list"));
    }

    @Test
    void createOfferWithoutStatusList_thenBadRequest() throws Exception {
        String minPayloadWithEmptySubject = "{\"metadata_credential_supported_id\": [\"%s\"], \"credential_subject_data\": {\"credential_subject_data\" : \"credential_subject_data\"}, \"status_lists\": [\"%s\"]}"
                .formatted(RandomStringUtils.insecure().next(10), statusRegistryUrl);

        mvc.perform(post(BASE_URL).contentType(MediaType.APPLICATION_JSON).content(minPayloadWithEmptySubject))
                .andExpect(status().isBadRequest())
                .andReturn();
    }

    @Test
    void getNotExistingStatusList_thenIsNotFound() throws Exception {
        var notExistingstatusListUUID = UUID.fromString("00000000-0000-0000-0000-000000000000");
        var requestUrl = String.format("%s/%s", STATUS_LIST_BASE_URL, notExistingstatusListUUID);
        String minPayloadWithEmptySubject = "{\"metadata_credential_supported_id\": [\"%s\"], \"credential_subject_data\": {\"credential_subject_data\" : \"credential_subject_data\"}, \"status_lists\": [\"%s\"]}"
                .formatted(RandomStringUtils.insecure().next(10), statusRegistryUrl);

        mvc.perform(get(requestUrl).contentType(MediaType.APPLICATION_JSON).content(minPayloadWithEmptySubject))
                .andExpect(status().isNotFound())
                .andReturn();
    }

    @Test
    void createOfferThenGetStatusList_thenSuccess() throws Exception {

        var type = "TOKEN_STATUS_LIST";
        var maxLength = 255;
        var bits = 2;
        var payload = String.format("{\"type\": \"%s\",\"maxLength\": %d,\"config\": {\"bits\": %d}}", type, maxLength,
                bits);

        var result = mvc.perform(post(STATUS_LIST_BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isOk())
                .andReturn();

        String offerCred = getMinimalPayloadForCredentialSupportedIdTest(null, null, statusRegistryUrl);

        mvc.perform(post(BASE_URL).contentType(MediaType.APPLICATION_JSON).content(offerCred))
                .andExpect(status().isOk())
                .andReturn();

        // check if next free index increased
        var statusListId = JsonPath.read(result.getResponse().getContentAsString(), "$.id");

        mvc.perform(get(STATUS_LIST_BASE_URL + "/" + statusListId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").isNotEmpty())
                .andExpect(jsonPath("$.statusRegistryUrl").isNotEmpty())
                .andExpect(jsonPath("$.maxListEntries").value(maxLength))
                .andExpect(jsonPath("$.remainingListEntries").value(maxLength - issuerMetadata.getIssuanceBatchSize()))
                .andExpect(jsonPath("$.maxListEntries").value(maxLength))
                .andExpect(jsonPath("$.config.bits").value(bits)).andExpect(jsonPath("$.config.purpose").isEmpty());
    }

    @Test
    void createStatusListWithPurpose_thenSuccess() throws Exception {
        var bits = 1;
        var purpose = "test";
        var payload = String.format("{\"type\": \"TOKEN_STATUS_LIST\",\"maxLength\": %d,\"config\": {\"bits\": %d, \"purpose\": \"%s\"}}", statusListProperties.getStatusListSizeLimit(), bits, purpose);

        var newStatusList = mvc.perform(post(STATUS_LIST_BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isOk())
                .andReturn();


        // check if get info endpoint return the same values
        mvc.perform(get(STATUS_LIST_BASE_URL + "/" + JsonPath.read(newStatusList.getResponse().getContentAsString(), "$.id")))
                .andExpect(jsonPath("$.config.bits").value(bits))
                .andExpect(jsonPath("$.config.purpose").value(purpose))
        ;
    }

    @Test
    void createStatusList_maxLengthExceeded_thenSuccess() throws Exception {
        var bits = 1;
        var payload = getCreateTokenStatusListPayload(statusListProperties.getStatusListSizeLimit() + 1, bits);
        var invalidTotalSize = (statusListProperties.getStatusListSizeLimit() + 1) * bits;

        var result = mvc.perform(post(STATUS_LIST_BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().is(HttpStatus.UNPROCESSABLE_CONTENT.value()))
                .andReturn().getResponse().getContentAsString();

        assertTrue(result.contains("statusListCreateDto: Status list has invalid size %s cannot exceed the maximum size limit of %s"
                .formatted(invalidTotalSize, statusListProperties.getStatusListSizeLimit())));
    }

    @Test
    void createStatusList_maxLengthExceededWithBits_thenUnprocessableEntity() throws Exception {
        var bits = 2;
        var invalidMaxLength = (statusListProperties.getStatusListSizeLimit() / bits) + 1;
        var payload = getCreateTokenStatusListPayload(invalidMaxLength, bits);
        var invalidTotalSize = invalidMaxLength * bits;

        var result = mvc.perform(post(STATUS_LIST_BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().is(HttpStatus.UNPROCESSABLE_CONTENT.value()))
                .andReturn().getResponse().getContentAsString();

        assertTrue(result.contains("statusListCreateDto: Status list has invalid size %s cannot exceed the maximum size limit of %s"
                .formatted(invalidTotalSize, statusListProperties.getStatusListSizeLimit())));
    }

    @Test
    void createStatusList_invalidConfig_thenUnprocessableEntity() throws Exception {
        var bits = 3;
        var validMaxLength = 100;
        var payload = getCreateTokenStatusListPayload(validMaxLength, bits);

        var result = mvc.perform(post(STATUS_LIST_BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().is(HttpStatus.UNPROCESSABLE_CONTENT.value()))
                .andReturn()
                .getResponse().getContentAsString();

        assertTrue(result.contains("config.bits: Bits can only be 1, 2, 4 or 8"));
    }

    @Test
    void createStatusList_invalidBitsAmount_thenBadRequest() throws Exception {
        var type = "TOKEN_STATUS_LIST";
        var invalidMaxLength = statusListProperties.getStatusListSizeLimit();
        var payload = String.format("{\"type\": \"%s\",\"maxLength\": %d,\"config\": null}", type, invalidMaxLength);

        var result = mvc.perform(post(STATUS_LIST_BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().is(HttpStatus.UNPROCESSABLE_CONTENT.value()))
                .andReturn().getResponse()
                .getContentAsString();

        assertTrue(result.contains("statusListCreateDto: Status list size cannot be evaluated due to missing infos in config"));
        assertTrue(result.contains("config: must not be null"));
    }

    @Test
    void updateStatusList_withInvalidStatusList_throwsException() throws Exception {

        doReturn(true).when(applicationProperties).isAutomaticStatusListSynchronizationDisabled();

        mvc.perform(post(STATUS_LIST_BASE_URL + "/" + statusListUUID)
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error_description").value("Not Found"));
    }

    @Test
    void updateStatusList_checkIfRegistryCalled_throwsException() throws Exception {

        var statusList = createStatusList();

        doReturn(true).when(applicationProperties).isAutomaticStatusListSynchronizationDisabled();

        var offer = createOffer(statusList);

        var accessToken = getAccessTokenFromDeeplink(mvc, offer.get("offer_deeplink").getAsString());

        var holderKeys = IntStream.range(0, issuerMetadata.getIssuanceBatchSize())
                .boxed()
                .map(i -> assertDoesNotThrow(() -> createPrivateKey("Test-Key-%s".formatted(i))))
                .toList();

        var credentialRequestString = getCredentialRequestString(mvc, holderKeys, applicationProperties, "university_example_sd_jwt");

        requestCredential(mvc, accessToken, credentialRequestString)
                .andExpect(status().isOk())
                .andReturn();

        //  revoke credential
        mvc.perform(patch(getUpdateUrl(UUID.fromString(offer.get("management_id").getAsString()), CredentialStatusTypeDto.REVOKED)))
                .andExpect(status().isOk());

        // should be only called once on status list create
        verify(statusBusinessApi, times(1)).updateStatusListEntry(any(), any(), any());
    }

    @Test
    void updateStatusList_checkIfRegistryCalledWithAutomaticUpdate_thenSuccess() throws Exception {

        var statusList = createStatusList();

        var offer = createOffer(statusList);

        var accessToken = getAccessTokenFromDeeplink(mvc, offer.get("offer_deeplink").getAsString());

        var holderKeys = IntStream.range(0, issuerMetadata.getIssuanceBatchSize())
                .boxed()
                .map(i -> assertDoesNotThrow(() -> createPrivateKey("Test-Key-%s".formatted(i))))
                .toList();

        var credentialRequestString = getCredentialRequestString(mvc, holderKeys, applicationProperties, "university_example_sd_jwt");

        requestCredential(mvc, accessToken, credentialRequestString)
                .andExpect(status().isOk())
                .andReturn();

        //  revoke credential
        mvc.perform(patch(getUpdateUrl(UUID.fromString(offer.get("management_id").getAsString()), CredentialStatusTypeDto.REVOKED)))
                .andExpect(status().isOk());

        // should be only called once (1) on status list create and once (1) on update
        verify(statusBusinessApi, times(1 + 1)).updateStatusListEntry(any(), any(), any());
    }

    @Test
    void updateStatusList_checkIfRegistryCalledWithAutomaticUpdateDisabled_thenSuccess() throws Exception {

        doReturn(true).when(applicationProperties).isAutomaticStatusListSynchronizationDisabled();

        var statusList = createStatusList();

        var offer = createOffer(statusList);

        var accessToken = getAccessTokenFromDeeplink(mvc, offer.get("offer_deeplink").getAsString());

        var holderKeys = IntStream.range(0, issuerMetadata.getIssuanceBatchSize())
                .boxed()
                .map(i -> assertDoesNotThrow(() -> createPrivateKey("Test-Key-%s".formatted(i))))
                .toList();

        var credentialRequestString = getCredentialRequestString(mvc, holderKeys, applicationProperties, "university_example_sd_jwt");

        requestCredential(mvc, accessToken, credentialRequestString)
                .andExpect(status().isOk())
                .andReturn();

        //  revoke credential
        mvc.perform(patch(getUpdateUrl(UUID.fromString(offer.get("management_id").getAsString()), CredentialStatusTypeDto.REVOKED)))
                .andExpect(status().isOk());

        // should be only called once on status list create
        verify(statusBusinessApi, times(1)).updateStatusListEntry(any(), any(), any());

        mvc.perform(post("/management/api/status-list" + "/" + statusList.get("id").getAsString()))
                .andExpect(status().isOk());

        // should be only called twice on status list create
        verify(statusBusinessApi, times(2)).updateStatusListEntry(any(), any(), any());
    }

    private String getCreateTokenStatusListPayload(int maxLength, int bits) {
        return String.format("{\"type\": \"TOKEN_STATUS_LIST\",\"maxLength\": %d,\"config\": {\"bits\": %d}}", maxLength, bits);
    }


    private JsonObject createOffer(JsonObject statusList) throws Exception {

        String jsonPayload = getMinimalPayloadForUniversityCredential(statusList.get("statusRegistryUrl").getAsString());

        var response = mvc.perform(post(BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonPayload))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        return JsonParser.parseString(response).getAsJsonObject();
    }

    public String getUpdateUrl(UUID id, CredentialStatusTypeDto credentialStatus) {
        return String.format("%s?credentialStatus=%s", getUrl(id), credentialStatus);
    }

    String getUrl(UUID id) {
        return String.format("%s/%s/status", BASE_URL, id);
    }

    private HSMProperties getHsmProperties(String keyId) {

        var hsmConfig = new HSMProperties();
        hsmConfig.setUserPin("209323");
        hsmConfig.setKeyId(keyId);
        hsmConfig.setKeyPin("209323");
        hsmConfig.setPkcs11Config("pkcs11-hsm");
        hsmConfig.setUser("user");
        hsmConfig.setHost("host");
        hsmConfig.setPort("1234");
        hsmConfig.setPassword("password");
        hsmConfig.setProxyUser("proxy-user");
        hsmConfig.setProxyPassword("proxy-password");
        return hsmConfig;
    }
}
