package ch.admin.bj.swiyu.issuer.management.infrastructure.web.controller;

import ch.admin.bj.swiyu.core.status.registry.client.api.StatusBusinessApiApi;
import ch.admin.bj.swiyu.core.status.registry.client.invoker.ApiClient;
import ch.admin.bj.swiyu.core.status.registry.client.model.StatusListEntryCreationDto;
import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.dto.credentialofferstatus.CredentialStatusTypeDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SignatureConfiguration;
import ch.admin.bj.swiyu.issuer.common.config.StatusListProperties;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusList;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusListRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusListType;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.service.JwsSignatureFacade;
import ch.admin.bj.swiyu.jwssignatureservice.factory.strategy.KeyStrategyException;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.apache.commons.lang3.RandomStringUtils;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.testcontainers.junit.jupiter.Testcontainers;
import reactor.core.publisher.Mono;

import java.util.Optional;
import java.util.UUID;
import java.util.stream.IntStream;

import static ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller.IssuanceV2TestUtils.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
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
    @Autowired
    private SwiyuProperties swiyuProperties;
    @Autowired
    private MockMvc mvc;
    @Autowired
    private StatusListProperties statusListProperties;
    @Autowired
    private StatusListRepository statusListRepository;
    @MockitoBean
    private StatusBusinessApiApi statusBusinessApi;
    @MockitoBean
    private JwsSignatureFacade jwsSignatureFacade;
    @Mock
    private ApiClient mockApiClient;
    @Autowired
    private IssuerMetadata issuerMetadata;
    @MockitoSpyBean
    private ApplicationProperties applicationProperties;


    @BeforeEach
    void setUp() throws JOSEException, KeyStrategyException {
        var statusListEntryCreationDto = new StatusListEntryCreationDto();
        statusListEntryCreationDto.setId(statusListUUID);
        statusListEntryCreationDto.setStatusRegistryUrl(statusRegistryUrl);

        when(statusBusinessApi.createStatusListEntry(swiyuProperties.businessPartnerId()))
                .thenReturn(Mono.just(statusListEntryCreationDto));
        when(statusBusinessApi.updateStatusListEntry(any(), any(), any())).thenReturn(Mono.empty());
        when(statusBusinessApi.getApiClient()).thenReturn(mockApiClient);
        when(mockApiClient.getBasePath()).thenReturn(statusRegistryUrl);

        final JWSSigner es256Signer = new ECDSASigner(new ECKeyGenerator(Curve.P_256).keyID("test-key").generate());
        when(jwsSignatureFacade.createSigner(any(SignatureConfiguration.class), any(), any()))
                .thenReturn(es256Signer);
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
                .andExpect(jsonPath("$.type").value(type))
                .andExpect(jsonPath("$.maxListEntries").value(maxLength))
                .andExpect(jsonPath("$.remainingListEntries").value(maxLength))
                .andExpect(jsonPath("$.config.bits").value(bits))
                .andReturn().getResponse()
                .getContentAsString();

        return JsonParser.parseString(result).getAsJsonObject();
    }

    @Test
    void createNewStatusListOverrideConfiguration_thenSuccess() throws Exception {
        final StatusListType type = StatusListType.TOKEN_STATUS_LIST;
        final int maxLength = 127;
        final int bits = 4;
        final String issuerId = "did:example:offer:override";
        final String verificationMethod = issuerId + "#key";
        final String keyId = "1052933";
        final String keyPin = "209323";
        final String payload = String.format("{\"type\": \"%s\",\"maxLength\": %d,\"config\": {\"bits\": %d},\"configuration_override\": {\"issuer_did\": \"%s\",\"verification_method\": \"%s\",\"key_id\": %s,\"key_pin\": %s}}", type, maxLength, bits, issuerId, verificationMethod, keyId, keyPin);

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
        assertEquals(type, newStatusList.getType());
        assertEquals(maxLength, newStatusList.getMaxLength());
        assertEquals(bits, newStatusList.getConfig().get("bits"));
        assertEquals(issuerId, newStatusList.getConfigurationOverride().issuerDid());
        assertEquals(verificationMethod, newStatusList.getConfigurationOverride().verificationMethod());
        assertEquals(keyId, newStatusList.getConfigurationOverride().keyId());
        assertEquals(keyPin, newStatusList.getConfigurationOverride().keyPin());

        verify(jwsSignatureFacade, atLeastOnce()).createSigner(
                same(statusListProperties),
                eq(keyId),
                eq(keyPin)
        );
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

        String offerCred = "{\"metadata_credential_supported_id\": [\"test\"], \"credential_subject_data\": {\"lastName\" : \"lastName\"}, \"status_lists\": [\"%s\"]}"
                .formatted(statusRegistryUrl);

        mvc.perform(post(BASE_URL).contentType(MediaType.APPLICATION_JSON).content(offerCred))
                .andExpect(status().isOk())
                .andReturn();

        // check if next free index increased
        var statusListId = JsonPath.read(result.getResponse().getContentAsString(), "$.id");

        mvc.perform(get(STATUS_LIST_BASE_URL + "/" + statusListId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").isNotEmpty())
                .andExpect(jsonPath("$.statusRegistryUrl").isNotEmpty())
                .andExpect(jsonPath("$.type").value(type))
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
    void createStatusList_invalidStatusListType_thenBadRequest() throws Exception {
        var type = "NOT_TOKEN_STATUS_LIST";
        var bits = 1;
        var payload = getCreateStatusListPayload(type, statusListProperties.getStatusListSizeLimit(), bits);

        mvc.perform(post(STATUS_LIST_BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isBadRequest());
    }

    @Test
    void createStatusList_maxLengthExceeded_thenSuccess() throws Exception {
        var bits = 1;
        var payload = getCreateTokenStatusListPayload(statusListProperties.getStatusListSizeLimit() + 1, bits);
        var invalidTotalSize = (statusListProperties.getStatusListSizeLimit() + 1) * bits;

        var result = mvc.perform(post(STATUS_LIST_BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isUnprocessableEntity())
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
                .andExpect(status().isUnprocessableEntity())
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
                .andExpect(status().isUnprocessableEntity())
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
                .andExpect(status().isUnprocessableEntity())
                .andReturn().getResponse()
                .getContentAsString();

        assertTrue(result.contains("statusListCreateDto: Status list size cannot be evaluated due to missing infos in config"));
        assertTrue(result.contains("config: must not be null"));
    }

    @Test
    void updateStatusList_withInvalidStatusList_throwsException() throws Exception {

        when(applicationProperties.isAutomaticStatusListSynchronizationDisabled()).thenReturn(true);

        mvc.perform(post(STATUS_LIST_BASE_URL + "/" + statusListUUID)
                        .contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error_description").value("Not Found"));
    }

    @Test
    void updateStatusList_checkIfRegistryCalled_throwsException() throws Exception {

        var statusList = createStatusList();

        when(applicationProperties.isAutomaticStatusListSynchronizationDisabled()).thenReturn(true);

        var offer = createOffer(statusList);

        var accessToken = getAccessTokenFromDeeplink(mvc, offer.get("offer_deeplink").getAsString());

        var holderKeys = IntStream.range(0, issuerMetadata.getIssuanceBatchSize())
                .boxed()
                .map(i -> assertDoesNotThrow(() -> createPrivateKeyV2("Test-Key-%s".formatted(i))))
                .toList();

        var credentialRequestString = getCredentialRequestStringV2(mvc, holderKeys, applicationProperties);

        requestCredentialV2(mvc, accessToken, credentialRequestString)
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
                .map(i -> assertDoesNotThrow(() -> createPrivateKeyV2("Test-Key-%s".formatted(i))))
                .toList();

        var credentialRequestString = getCredentialRequestStringV2(mvc, holderKeys, applicationProperties);

        requestCredentialV2(mvc, accessToken, credentialRequestString)
                .andExpect(status().isOk())
                .andReturn();

        //  revoke credential
        mvc.perform(patch(getUpdateUrl(UUID.fromString(offer.get("management_id").getAsString()), CredentialStatusTypeDto.REVOKED)))
                .andExpect(status().isOk());

        // should be only called once on status list create
        verify(statusBusinessApi, times(issuerMetadata.getIssuanceBatchSize() + 1)).updateStatusListEntry(any(), any(), any());
    }

    @Test
    void updateStatusList_checkIfRegistryCalledWithAutomaticUpdateDisabled_thenSuccess() throws Exception {

        when(applicationProperties.isAutomaticStatusListSynchronizationDisabled()).thenReturn(true);

        var statusList = createStatusList();

        var offer = createOffer(statusList);

        var accessToken = getAccessTokenFromDeeplink(mvc, offer.get("offer_deeplink").getAsString());

        var holderKeys = IntStream.range(0, issuerMetadata.getIssuanceBatchSize())
                .boxed()
                .map(i -> assertDoesNotThrow(() -> createPrivateKeyV2("Test-Key-%s".formatted(i))))
                .toList();

        var credentialRequestString = getCredentialRequestStringV2(mvc, holderKeys, applicationProperties);

        requestCredentialV2(mvc, accessToken, credentialRequestString)
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

    private String getCreateStatusListPayload(String type, int maxLength, int bits) {
        return String.format("{\"type\": \"%s\",\"maxLength\": %d,\"config\": {\"bits\": %d}}", type, maxLength, bits);
    }

    private JsonObject createOffer(JsonObject statusList) throws Exception {

        String offerData = """
                {
                    "type": "UniversityDegreeCredential",
                    "name": "Bachelor of Science"
                  }""";
        // We add the data to the other parts needed for offering a credential
        String jsonPayload = String.format("""
                {
                  "metadata_credential_supported_id": ["university_example_sd_jwt"],
                  "credential_subject_data": %s,
                  "offer_validity_seconds": 36000,
                  "status_lists": ["%s"]
                }
                """, offerData, statusList.get("statusRegistryUrl").getAsString());

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

}