/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.infrastructure.web.controller;

import ch.admin.bj.swiyu.core.status.registry.client.api.StatusBusinessApiApi;
import ch.admin.bj.swiyu.core.status.registry.client.invoker.ApiClient;
import ch.admin.bj.swiyu.core.status.registry.client.model.StatusListEntryCreationDto;
import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.api.common.ConfigurationOverrideDto;
import ch.admin.bj.swiyu.issuer.api.credentialoffer.CreateCredentialRequestDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.CredentialStatusTypeDto;
import ch.admin.bj.swiyu.issuer.api.statuslist.StatusListConfigDto;
import ch.admin.bj.swiyu.issuer.api.statuslist.StatusListCreateDto;
import ch.admin.bj.swiyu.issuer.api.statuslist.StatusListTypeDto;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.common.exception.ResourceNotFoundException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import com.jayway.jsonpath.JsonPath;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
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
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.junit.jupiter.Testcontainers;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest()
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
@Transactional
class CredentialOfferStatusIT {

    public static final String STATUS_LIST_BASE_URL = "/management/api/status-list";
    public static final String MANAGEMENT_BASE_URL = "/management/api/credentials";

    private static final int STATUS_LIST_MAX_LENGTH = 2;
    private static final String STATUS_REGISTRY_URL_TEMPLATE = "https://status-service-mock.bit.admin.ch/api/v1/statuslist/%s.jwt";

    private final UUID statusListUUID = UUID.randomUUID();
    private final String statusRegistryUrl = STATUS_REGISTRY_URL_TEMPLATE.formatted(statusListUUID);

    @Autowired
    protected SwiyuProperties swiyuProperties;

    @Autowired
    protected MockMvc mvc;
    protected CredentialOfferTestHelper testHelper;
    @Autowired
    private CredentialOfferRepository credentialOfferRepository;
    @Autowired
    private StatusListRepository statusListRepository;
    @Autowired
    private CredentialOfferStatusRepository credentialOfferStatusRepository;
    @Autowired
    private ObjectMapper objectMapper;
    @MockitoBean
    private StatusBusinessApiApi statusBusinessApi;
    @Mock
    private ApiClient mockApiClient;
    private UUID id;

    @BeforeEach
    void setupTest() throws Exception {
        testHelper = new CredentialOfferTestHelper(mvc, credentialOfferRepository, credentialOfferStatusRepository, statusListRepository,
                statusRegistryUrl, objectMapper);
        var statusListEntryCreationDto = new StatusListEntryCreationDto();
        statusListEntryCreationDto.setId(statusListUUID);
        statusListEntryCreationDto.setStatusRegistryUrl(statusRegistryUrl);

        when(statusBusinessApi.createStatusListEntry(swiyuProperties.businessPartnerId()))
                .thenReturn(statusListEntryCreationDto);
        when(statusBusinessApi.getApiClient()).thenReturn(mockApiClient);
        when(mockApiClient.getBasePath()).thenReturn(statusRegistryUrl);

        // Mock removing access to registry
        // Add status list
        mvc.perform(post("/management/api/status-list")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(
                                "{\"type\": \"TOKEN_STATUS_LIST\",\"maxLength\": %s,\"config\": {\"bits\": 2}}".formatted(STATUS_LIST_MAX_LENGTH)))
                .andExpect(status().isOk());
        // Add Test Offer
        id = testHelper.createBasicOfferJsonAndGetUUID();
    }

    @Test
    void testGetOfferStatus_thenSuccess() throws Exception {

        CredentialStatusTypeDto expectedStatus = CredentialStatusTypeDto.OFFERED;

        mvc.perform(get(testHelper.getUrl(id)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(expectedStatus.toString()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"READY", "CANCELLED", "SUSPENDED", "REVOKED"})
    void testUpdateWithSameStatus_thenOk(String value) throws Exception {
        var vcId = testHelper.createStatusListLinkedOfferAndGetUUID();
        testHelper.changeOfferStatus(vcId, CredentialStatusType.valueOf(value));

        mvc.perform(patch(testHelper.getUpdateUrl(vcId, CredentialStatusTypeDto.valueOf(value))))
                .andExpect(status().isOk());

        mvc.perform(get(testHelper.getUrl(vcId)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(CredentialStatusTypeDto.valueOf(value).toString()));
    }

    @Test
    void testUpdateOfferStatusWithOfferedWhenOffered1_thenBadRequest() throws Exception {

        CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.ISSUED;

        mvc.perform(patch(testHelper.getUpdateUrl(id, newStatus)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void testUpdateOfferStatusWithRevokedWhenIssued_thenSuccess() throws Exception {
        UUID vcRevokedId = testHelper.createIssueAndSetStateOfVc(CredentialStatusTypeDto.REVOKED);

        var offer = credentialOfferRepository.findById(vcRevokedId).get();
        Set<CredentialOfferStatus> byOfferStatusId = credentialOfferStatusRepository.findByOfferStatusId(offer.getId());
        assertEquals(CredentialStatusType.REVOKED, offer.getCredentialStatus());
        assertEquals(1, byOfferStatusId.size());
        var offerStatus = byOfferStatusId.stream().findFirst().get();
        assertEquals(0, offerStatus.getIndex(), "Should be the very first index");
        var statusList = statusListRepository.findById(offerStatus.getId().getStatusListId()).get();
        assertEquals(1, statusList.getNextFreeIndex(), "Should NOT have advanced the counter");
        var tokenStatusList = testHelper.loadTokenStatusListToken((Integer) statusList.getConfig().get("bits"), statusList.getStatusZipped());
        assertEquals(1, tokenStatusList.getStatus(0), "Should be revoked");
        assertEquals(0, tokenStatusList.getStatus(1), "Should not be revoked");

        UUID vcSuspendedId = testHelper.createIssueAndSetStateOfVc(CredentialStatusTypeDto.SUSPENDED);
        offer = credentialOfferRepository.findById(vcSuspendedId).get();
        assertEquals(CredentialStatusType.SUSPENDED, offer.getCredentialStatus());
        byOfferStatusId = credentialOfferStatusRepository.findByOfferStatusId(offer.getId());
        offerStatus = byOfferStatusId.stream().findFirst().get();
        assertEquals(1, offerStatus.getIndex(), "Should be the the second entry");
        statusList = statusListRepository.findById(offerStatus.getId().getStatusListId()).get();
        assertEquals(2, statusList.getNextFreeIndex(), "Should have advanced the counter");
        tokenStatusList = testHelper.loadTokenStatusListToken((Integer) statusList.getConfig().get("bits"),
                statusList.getStatusZipped());
        assertEquals(1, tokenStatusList.getStatus(0), "Should be still revoked");
        assertEquals(2, tokenStatusList.getStatus(1), "Should be suspended");
        assertEquals(0, tokenStatusList.getStatus(2), "Should not be revoked");

        CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.ISSUED;
        mvc.perform(patch(testHelper.getUpdateUrl(vcSuspendedId, newStatus)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(newStatus.toString()));
        offer = credentialOfferRepository.findById(vcSuspendedId).get();
        assertEquals(CredentialStatusType.ISSUED, offer.getCredentialStatus());
        byOfferStatusId = credentialOfferStatusRepository.findByOfferStatusId(offer.getId());
        offerStatus = byOfferStatusId.stream().findFirst().get();
        statusList = statusListRepository.findById(offerStatus.getId().getStatusListId()).get();
        tokenStatusList = testHelper.loadTokenStatusListToken((Integer) statusList.getConfig().get("bits"),
                statusList.getStatusZipped());
        assertEquals(1, tokenStatusList.getStatus(0), "Should be still revoked");
        assertEquals(0, tokenStatusList.getStatus(1), "Should not be suspended any more");
    }

    @Test
    void testCreateOfferWhenExceedStatusListMaximum_thenBadRequest() throws Exception {
        for (var i = 0; i < STATUS_LIST_MAX_LENGTH; i++) {
            testHelper.createStatusListLinkedOfferAndGetUUID();
        }
        String payload = "{\"metadata_credential_supported_id\": [\"test\"], \"credential_subject_data\": {\"credential_subject_data\" : \"credential_subject_data\"}, \"status_lists\": [\"%s\"]}"
                .formatted(statusRegistryUrl);
        mvc
                .perform(post(CredentialOfferTestHelper.BASE_URL).contentType("application/json").content(payload))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.detail")
                        .value(
                                Matchers.allOf(
                                        Matchers.containsString(statusRegistryUrl),
                                        Matchers.containsString("exceed"),
                                        Matchers.containsString(String.valueOf(STATUS_LIST_MAX_LENGTH)))));

    }

    @Nested
    @DisplayName("Test deferred flow")
    class CredentialFlow {
    }

    @Nested
    @DisplayName("Test deferred flow")
    class Deferred {
        @Test
        void testUpdateOfferStatusWithDeferred_thenBadRequest() throws Exception {

            CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.READY;

            mvc.perform(patch(testHelper.getUpdateUrl(id, newStatus)))
                    .andExpect(status().isBadRequest());
        }

        @Test
        void testUpdateOfferStatusWithReadyWhenDeferred_thenOk() throws Exception {

            CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.READY;

            // Set the status to DEFERRED as this is done by the oid4vci
            var offer = credentialOfferRepository.findById(id).orElseThrow(() -> new ResourceNotFoundException(String.format("Credential %s not found", id)));

            offer.changeStatus(CredentialStatusType.DEFERRED);

            credentialOfferRepository.save(offer);

            mvc.perform(patch(testHelper.getUpdateUrl(id, newStatus)))
                    .andExpect(status().isOk());
        }
    }

    @Nested
    @DisplayName("Test invalid status inputs")
    class InvalidStatusInputs {

        @ParameterizedTest
        @ValueSource(strings = {"IN_PROGRESS", "DEFERRED", "ISSUED"})
        void testUpdateOfferStatusWhenPreIssuedWhitSuspended_thenBadRequest(String value) throws Exception {
            var originalState = CredentialStatusTypeDto.OFFERED.toString();
            var newValue = CredentialStatusTypeDto.valueOf(value);
            var vcId = testHelper.createBasicOfferJsonAndGetUUID();

            mvc.perform(patch(testHelper.getUpdateUrl(vcId, newValue)))
                    .andExpect(status().isBadRequest());

            mvc.perform(get(testHelper.getUrl(vcId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(originalState));
        }

        @Test
        void testUpdateOfferStatusWithOfferedWhenInProgress_thenBadRequest() throws Exception {
            var originalState = CredentialStatusTypeDto.IN_PROGRESS.toString();
            var vcId = testHelper.createBasicOfferJsonAndGetUUID();
            testHelper.changeOfferStatus(vcId, CredentialStatusType.valueOf(originalState));

            mvc.perform(patch(testHelper.getUpdateUrl(vcId, CredentialStatusTypeDto.OFFERED)))
                    .andExpect(status().isBadRequest());

            mvc.perform(get(testHelper.getUrl(vcId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(originalState));
        }

        @ParameterizedTest
        @ValueSource(strings = {"OFFERED", "CANCELLED", "IN_PROGRESS", "DEFERRED", "READY", "EXPIRED"})
        void testUpdateOfferWithIssuedWhenPreIssued_thenBadRequest(String originalState) throws Exception {

            var newValue = CredentialStatusTypeDto.ISSUED;
            var vcId = testHelper.createBasicOfferJsonAndGetUUID();
            testHelper.changeOfferStatus(vcId, CredentialStatusType.valueOf(originalState));

            mvc.perform(patch(testHelper.getUpdateUrl(vcId, newValue)))
                    .andExpect(status().isBadRequest());

            mvc.perform(get(testHelper.getUrl(vcId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(originalState));
        }
    }

    @Nested
    @DisplayName("Test suspension of offers")
    class Suspended {
        private final CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.SUSPENDED;

        @ParameterizedTest
        @ValueSource(strings = {"OFFERED", "CANCELLED", "IN_PROGRESS", "DEFERRED", "READY", "EXPIRED", "CANCELLED"})
        void testUpdateOfferStatusWhenPreIssuedWhitSuspended_thenBadRequest(String value) throws Exception {
            var vcId = testHelper.createStatusListLinkedOfferAndGetUUID();
            testHelper.changeOfferStatus(vcId, CredentialStatusType.valueOf(value));

            mvc.perform(patch(testHelper.getUpdateUrl(vcId, newStatus)))
                    .andExpect(status().isBadRequest());

            mvc.perform(get(testHelper.getUrl(vcId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(value));
        }

        @ParameterizedTest
        @ValueSource(strings = {"REVOKED"})
        void testUpdateOfferStatusWhenTerminalWhitSuspended_thenBadRequest(String value) throws Exception {
            var vcId = testHelper.createIssueAndSetStateOfVc(CredentialStatusTypeDto.valueOf(value));

            mvc.perform(patch(testHelper.getUpdateUrl(vcId, newStatus)))
                    .andExpect(status().isBadRequest());

            mvc.perform(get(testHelper.getUrl(vcId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(value));
        }

        @ParameterizedTest
        @ValueSource(strings = {"ISSUED", "SUSPENDED"})
        void testUpdateOfferStatusWhenSuspended_thenSuccess(String value) throws Exception {

            var vcId = testHelper.createIssueAndSetStateOfVc(CredentialStatusTypeDto.valueOf(value));

            mvc.perform(patch(testHelper.getUpdateUrl(vcId, newStatus)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(CredentialStatusTypeDto.SUSPENDED.toString()));
        }
    }

    @Nested
    @DisplayName("Test revocation of offers")
    class Revoked {
        private final CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.REVOKED;

        @ParameterizedTest
        @ValueSource(strings = {"OFFERED", "IN_PROGRESS", "DEFERRED", "READY"})
        void testUpdateOfferStatusWhenPreIssuedWithRevoked_thenIsOk(String value) throws Exception {
            var vcId = testHelper.createStatusListLinkedOfferAndGetUUID();
            testHelper.changeOfferStatus(id, CredentialStatusType.valueOf(value));

            mvc.perform(patch(testHelper.getUpdateUrl(vcId, newStatus)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(CredentialStatusTypeDto.CANCELLED.toString()));

            mvc.perform(get(testHelper.getUrl(vcId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(CredentialStatusTypeDto.CANCELLED.toString()));
        }

        @ParameterizedTest
        @ValueSource(strings = {"EXPIRED", "CANCELLED"})
        void testUpdateOfferStatusWhenTerminalState_thenBadRequest(String value) throws Exception {
            var vcId = testHelper.createStatusListLinkedOfferAndGetUUID();
            testHelper.changeOfferStatus(vcId, CredentialStatusType.valueOf(value));

            mvc.perform(patch(testHelper.getUpdateUrl(vcId, newStatus)))
                    .andExpect(status().isBadRequest());

            mvc.perform(get(testHelper.getUrl(vcId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(value));
        }

        @ParameterizedTest
        @ValueSource(strings = {"SUSPENDED", "ISSUED", "REVOKED"})
        void testUpdateOfferStatusWhenPossibleState_thenIsOk(String value) throws Exception {
            var vcId = testHelper.createIssueAndSetStateOfVc(CredentialStatusTypeDto.valueOf(value));

            mvc.perform(patch(testHelper.getUpdateUrl(vcId, newStatus)))
                    .andExpect(status().isOk());
        }

        /**
         * Should fail because no way of revocation is available
         */
        @Test
        void testUpdateOfferStatusWithRevokedWhenIssuedWithoutStatusList_thenBadRequest() throws Exception {

            testHelper.updateStatusForEntity(id, CredentialStatusType.ISSUED);

            mvc.perform(patch(testHelper.getUpdateUrl(id, newStatus)))
                    .andExpect(status().isBadRequest());
        }

        @Test
        void testUpdateOfferStatusWithRevokedWhenRevoked_thenOk() throws Exception {

            mvc.perform(patch(testHelper.getUpdateUrl(id, newStatus)))
                    .andExpect(status().isOk());
        }
    }

    @Nested
    @DisplayName("Test cancellation of offers")
    class Cancelled {

        private final CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.CANCELLED;

        @ParameterizedTest
        @ValueSource(strings = {"OFFERED", "IN_PROGRESS", "DEFERRED", "READY", "CANCELLED", "REVOKED"})
        void testCancelWhenPreIssued_thenOk(String value) throws Exception {
            var vcId = testHelper.createStatusListLinkedOfferAndGetUUID();
            testHelper.changeOfferStatus(id, CredentialStatusType.valueOf(value));

            mvc.perform(patch(testHelper.getUpdateUrl(vcId, newStatus)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(CredentialStatusTypeDto.CANCELLED.toString()));

            mvc.perform(get(testHelper.getUrl(vcId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(CredentialStatusTypeDto.CANCELLED.toString()));
        }

        @ParameterizedTest
        @ValueSource(strings = {"REVOKED", "SUSPENDED", "ISSUED"})
        void testCancelWhenPostIssued_thenBadRequest(String value) throws Exception {
            var originalState = CredentialStatusTypeDto.valueOf(value);
            var vcId = testHelper.createIssueAndSetStateOfVc(originalState);
            testHelper.updateStatusForEntity(vcId, CredentialStatusType.valueOf(value));

            mvc.perform(patch(testHelper.getUpdateUrl(vcId, newStatus)))
                    .andExpect(status().isBadRequest());

            mvc.perform(get(testHelper.getUrl(vcId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(originalState.toString()));
        }

        @Test
        void testUpdateOfferStatusWithCancelledWhenExpired_thenBadRequest() throws Exception {
            var originalState = CredentialStatusTypeDto.EXPIRED;
            var vcId = testHelper.createBasicOfferJsonAndGetUUID();
            testHelper.changeOfferStatus(vcId, CredentialStatusType.valueOf(originalState.toString()));

            mvc.perform(patch(testHelper.getUpdateUrl(vcId, newStatus)))
                    .andExpect(status().isBadRequest());

            mvc.perform(get(testHelper.getUrl(vcId)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value(originalState.toString()));
        }
    }

    @Test
    void testCreateCredentialWhenReferencingNewlyCreatedStatusList_thenOk() throws Exception {
        final UUID statusRegistryId = UUID.randomUUID();
        final String newStatusRegistryUrl = STATUS_REGISTRY_URL_TEMPLATE.formatted(statusRegistryId);

        final StatusListEntryCreationDto statusListEntryCreationDto = new StatusListEntryCreationDto();
        statusListEntryCreationDto.setId(statusRegistryId);
        statusListEntryCreationDto.setStatusRegistryUrl(newStatusRegistryUrl);

        when(statusBusinessApi.createStatusListEntry(swiyuProperties.businessPartnerId())).thenReturn(statusListEntryCreationDto);
        when(statusBusinessApi.getApiClient()).thenReturn(mockApiClient);
        when(mockApiClient.getBasePath()).thenReturn(newStatusRegistryUrl);

        final String issuerDid = "did:override:example:com";
        final String verificationMethod = issuerDid + "#key1";
        final ConfigurationOverrideDto configurationOverrideDto = new ConfigurationOverrideDto(issuerDid, verificationMethod, null, null);

        final StatusListCreateDto statusListCreateDto = StatusListCreateDto.builder()
                .type(StatusListTypeDto.TOKEN_STATUS_LIST)
                .maxLength(255)
                .config(StatusListConfigDto.builder().purpose("Test purpose").bits(4).build())
                .configurationOverride(configurationOverrideDto)
                .build();

        final MvcResult result = mvc.perform(post(STATUS_LIST_BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(statusListCreateDto)))
                .andExpect(status().isOk()).andReturn();

        final String savedStatusRegistryUrl = JsonPath.read(result.getResponse().getContentAsString(), "$.statusRegistryUrl");
        assertEquals(newStatusRegistryUrl, savedStatusRegistryUrl);

        final CreateCredentialRequestDto createCredentialRequestDtoValid = CredentialOfferTestHelper
                .buildCreateCredentialRequestOverride(
                        List.of(savedStatusRegistryUrl),
                        issuerDid,
                        verificationMethod
                );

        mvc.perform(post(MANAGEMENT_BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createCredentialRequestDtoValid)))
                .andExpect(status().isOk())
                .andReturn();

        final CreateCredentialRequestDto createCredentialRequestDtoInvalidDid = CredentialOfferTestHelper
                .buildCreateCredentialRequestOverride(
                        List.of(savedStatusRegistryUrl),
                        issuerDid + "not-the-same",
                        verificationMethod
                );

        mvc.perform(post(MANAGEMENT_BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createCredentialRequestDtoInvalidDid)))
                .andExpect(status().isBadRequest())
                .andReturn();

        final CreateCredentialRequestDto createCredentialRequestDtoInvalidVerification = CredentialOfferTestHelper
                .buildCreateCredentialRequestOverride(
                        List.of(savedStatusRegistryUrl),
                        issuerDid,
                        verificationMethod + "not-the-same"
                );

        mvc.perform(post(MANAGEMENT_BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(createCredentialRequestDtoInvalidVerification)))
                .andExpect(status().isBadRequest())
                .andReturn();
    }

}