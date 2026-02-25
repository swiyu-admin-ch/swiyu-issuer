package ch.admin.bj.swiyu.issuer.management.infrastructure.web.controller;

import ch.admin.bj.swiyu.core.status.registry.client.api.StatusBusinessApiApi;
import ch.admin.bj.swiyu.core.status.registry.client.invoker.ApiClient;
import ch.admin.bj.swiyu.core.status.registry.client.model.StatusListEntryCreationDto;
import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.dto.credentialoffer.CreateCredentialOfferRequestDto;
import ch.admin.bj.swiyu.issuer.dto.credentialoffer.CredentialWithDeeplinkResponseDto;
import ch.admin.bj.swiyu.issuer.dto.credentialofferstatus.CredentialStatusTypeDto;
import ch.admin.bj.swiyu.issuer.dto.statuslist.StatusListDto;
import ch.admin.bj.swiyu.issuer.dto.statuslist.StatusListTypeDto;
import ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller.IssuanceV2TestUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.ECKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.junit.jupiter.Testcontainers;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static ch.admin.bj.swiyu.issuer.oid4vci.test.CredentialOfferTestData.getUniversityCredentialSubjectData;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest()
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
//@Transactional selecting indexes view does not work with transactional
class CredentialManagementStatusIT {

    private static final int STATUS_LIST_MAX_LENGTH = 9;
    private static final String CREDENTIAL_MANAGEMENT_BASE_URL = "/management/api/credentials";

    @Autowired
    private SwiyuProperties swiyuProperties;

    @Autowired
    private ApplicationProperties applicationProperties;

    @Autowired
    private IssuerMetadata issuerMetadata;

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private CredentialOfferRepository credentialOfferRepository;

    @Autowired
    private CredentialOfferStatusRepository credentialOfferStatusRepository;

    @Autowired
    private StatusListRepository statusListRepository;

    private StatusListTestHelper statusListTestHelper;

    @MockitoBean
    private StatusBusinessApiApi statusBusinessApi;

    @Mock
    private ApiClient mockApiClient;

    private CredentialWithDeeplinkResponseDto credentialManagementOffer;

    private String statusListUri;

    @BeforeEach
    void setUp() throws Exception {

        statusListTestHelper = new StatusListTestHelper(mvc, objectMapper);
        final StatusListEntryCreationDto statusListEntry = statusListTestHelper.buildStatusListEntry();
        when(statusBusinessApi.createStatusListEntry(swiyuProperties.businessPartnerId())).thenReturn(Mono.just(statusListEntry));
        when(statusBusinessApi.updateStatusListEntry(any(), any(), any())).thenReturn(Mono.empty());
        when(statusBusinessApi.getApiClient()).thenReturn(mockApiClient);
        when(mockApiClient.getBasePath()).thenReturn(statusListEntry.getStatusRegistryUrl());

        final StatusListDto statusListDto = assertDoesNotThrow(() -> statusListTestHelper.createStatusList(
                StatusListTypeDto.TOKEN_STATUS_LIST,
                1000,
                null,
                2,
                null,
                null,
                null,
                null));

        statusListUri = statusListDto.getStatusRegistryUrl();

        credentialManagementOffer = prepareIssuedCredential();
    }

    @Transactional
    @ParameterizedTest
    @EnumSource(value = CredentialStatusTypeDto.class, names = {"SUSPENDED", "REVOKED", "ISSUED"})
    void testUpdateWithCorrectValues_thenOk(CredentialStatusTypeDto value) throws Exception {

        changeCredentialManagementStatus(credentialManagementOffer.getManagementId(), value);
    }

    @Transactional
    @ParameterizedTest
    @EnumSource(value = CredentialStatusTypeDto.class, names = {"SUSPENDED", "REVOKED", "ISSUED"})
    void testUpdateWithSameStatus_thenOk(CredentialStatusTypeDto value) throws Exception {

        changeCredentialManagementStatus(credentialManagementOffer.getManagementId(), value);

        changeCredentialManagementStatus(credentialManagementOffer.getManagementId(), value);
    }

    @Transactional
    @ParameterizedTest
    @EnumSource(value = CredentialStatusTypeDto.class, names = {"READY", "CANCELLED"})
    void testUpdateWithPreIssuanceStatus_thenBadRequest(CredentialStatusTypeDto value) throws Exception {

        mvc.perform(patch(getUpdateUrl(credentialManagementOffer.getManagementId(), value)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error_description").value("Bad Request"))
                .andExpect(jsonPath("$.detail").exists());
    }

    @Transactional
    @ParameterizedTest
    @EnumSource(value = CredentialStatusTypeDto.class, names = {"SUSPENDED", "REVOKED", "ISSUED"})
    void testUpdateWithPreIssuanceReadyStatus_thenBadRequest(CredentialStatusTypeDto value) throws Exception {

        changeCredentialManagementStatus(credentialManagementOffer.getManagementId(), value);

        mvc.perform(patch(getUpdateUrl(credentialManagementOffer.getManagementId(), CredentialStatusTypeDto.READY)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error_description").value("Bad Request"))
                .andExpect(jsonPath("$.detail").exists());
    }

    @Transactional
    @ParameterizedTest
    @EnumSource(value = CredentialStatusTypeDto.class, names = {"SUSPENDED", "REVOKED", "ISSUED"})
    void testUpdateWithPreIssuanceCancelledStatus_thenBadRequest(CredentialStatusTypeDto value) throws Exception {

        changeCredentialManagementStatus(credentialManagementOffer.getManagementId(), value);

        mvc.perform(patch(getUpdateUrl(credentialManagementOffer.getManagementId(), CredentialStatusTypeDto.CANCELLED)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error_description").value("Bad Request"))
                .andExpect(jsonPath("$.detail").exists());
    }

    @Transactional
    @ParameterizedTest
    @EnumSource(value = CredentialStatusTypeDto.class, names = {"SUSPENDED", "ISSUED", "REVOKED"})
    void testUpdateOfferRevocation_thenIsOk(CredentialStatusTypeDto value) throws Exception {
        changeCredentialManagementStatus(credentialManagementOffer.getManagementId(), value);

        changeCredentialManagementStatus(credentialManagementOffer.getManagementId(), CredentialStatusTypeDto.REVOKED);
    }

    @Transactional
    @Test
    void testUpdateOfferIssuanceWhenRevoked_thenBadRequest() throws Exception {

        changeCredentialManagementStatus(credentialManagementOffer.getManagementId(), CredentialStatusTypeDto.REVOKED);

        mvc.perform(patch(getUpdateUrl(credentialManagementOffer.getManagementId(), CredentialStatusTypeDto.ISSUED)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error_description").value("Bad Request"))
                .andExpect(jsonPath("$.detail").exists());
    }

    @Transactional
    @Test
    void testUpdateOfferStatusSuspendedWithRevoked_thenSuccess() throws Exception {
        changeCredentialManagementStatus(credentialManagementOffer.getManagementId(), CredentialStatusTypeDto.SUSPENDED);

        changeCredentialManagementStatus(credentialManagementOffer.getManagementId(), CredentialStatusTypeDto.REVOKED);
    }

    @Transactional
    @ParameterizedTest
    @EnumSource(value = CredentialStatusTypeDto.class, names = {"ISSUED", "SUSPENDED"})
    void testUpdateOfferStatusWhenSuspended_thenSuccess(CredentialStatusTypeDto value) throws Exception {

        changeCredentialManagementStatus(credentialManagementOffer.getManagementId(), value);

        changeCredentialManagementStatus(credentialManagementOffer.getManagementId(), CredentialStatusTypeDto.SUSPENDED);
    }

    @Test
    void testUpdateOfferStatusWithRevokedWhenIssued_thenSuccess() throws Exception {

        assertThat(STATUS_LIST_MAX_LENGTH).as("This test requires more than 9 indexes").isGreaterThanOrEqualTo(9);
        Set<Integer> unusedIndexes = IntStream.range(0, STATUS_LIST_MAX_LENGTH).boxed().collect(Collectors.toSet());
        // Add Revoked VCS
        changeCredentialManagementStatus(credentialManagementOffer.getManagementId(), CredentialStatusTypeDto.REVOKED);

        var offer = credentialOfferRepository.findById(UUID.fromString(String.valueOf(credentialManagementOffer.getOfferId()))).orElseThrow();

        Set<CredentialOfferStatus> revokedOfferStatus = credentialOfferStatusRepository.findByOfferId(credentialManagementOffer.getOfferId());
        assertThat(revokedOfferStatus)
                .as("Expecting test configuration to provide batch size of 10")
                .hasSize(10);
        var offerIds = revokedOfferStatus.stream()
                .map(CredentialOfferStatus::getId)
                .map(CredentialOfferStatusKey::getOfferId)
                .distinct()
                .toList();
        assertThat(offerIds)
                .as("All status entries should be of the same offer")
                .hasSize(1);
        unusedIndexes.removeAll(revokedOfferStatus.stream().map(CredentialOfferStatus::getId).map(CredentialOfferStatusKey::getIndex).collect(Collectors.toSet()));
        assertEquals(CredentialStatusManagementType.REVOKED, offer.getCredentialManagement().getCredentialManagementStatus());
        var statusListId = assertDoesNotThrow(() -> revokedOfferStatus.stream().findFirst().orElseThrow().getId().getStatusListId());
        var statusList = assertDoesNotThrow(() -> statusListRepository.findById(statusListId).orElseThrow());

        var tokenStatusList = TokenStatusListToken.loadTokenStatusListToken((Integer) statusList.getConfig().get("bits"), statusList.getStatusZipped(), 204800);
        for (var offerStatus : revokedOfferStatus) {
            assertThat(tokenStatusList.getStatus(offerStatus.getId().getIndex())).as("VC has been revoked").isEqualTo(1);
        }
        for (Integer index : unusedIndexes) {
            assertThat(tokenStatusList.getStatus(index)).as("Index has not been used and not revoked").isZero();
        }
        var suspendedMgmt = prepareIssuedCredential();

        changeCredentialManagementStatus(suspendedMgmt.getManagementId(), CredentialStatusTypeDto.SUSPENDED);

        offer = credentialOfferRepository.findById(UUID.fromString(String.valueOf(suspendedMgmt.getOfferId()))).orElseThrow();
        assertEquals(CredentialStatusManagementType.SUSPENDED, offer.getCredentialManagement().getCredentialManagementStatus());
        var suspendedOfferStatus = credentialOfferStatusRepository.findByOfferId(offer.getId());
        var suspendedIndexes = suspendedOfferStatus.stream()
                .map(CredentialOfferStatus::getId)
                .map(CredentialOfferStatusKey::getIndex)
                .collect(Collectors.toSet());
        unusedIndexes.removeAll(suspendedIndexes);

        statusList = assertDoesNotThrow(() -> statusListRepository.findById(statusListId).orElseThrow());
        tokenStatusList = TokenStatusListToken.loadTokenStatusListToken((Integer) statusList.getConfig().get("bits"), statusList.getStatusZipped(), 204800);

        for (var offerStatus : suspendedOfferStatus) {
            assertThat(tokenStatusList.getStatus(offerStatus.getId().getIndex())).as("VC has been suspended").isEqualTo(2);
        }
        for (var offerStatus : revokedOfferStatus) {
            assertThat(tokenStatusList.getStatus(offerStatus.getId().getIndex())).as("VC has been still revoked").isEqualTo(1);
        }
        for (Integer index : unusedIndexes) {
            assertThat(tokenStatusList.getStatus(index)).as("Index is still unused / valid").isZero();
        }

        CredentialStatusTypeDto newStatus = CredentialStatusTypeDto.ISSUED;
        changeCredentialManagementStatus(suspendedMgmt.getManagementId(), newStatus);

        var issuedOffer = credentialOfferRepository.findById(offer.getId()).orElseThrow();
        assertEquals(CredentialOfferStatusType.ISSUED, issuedOffer.getCredentialStatus());
        var issuedOfferStatus = credentialOfferStatusRepository.findByOfferId(issuedOffer.getId());
        var unsuspendedIndexes = issuedOfferStatus.stream()
                .map(CredentialOfferStatus::getId)
                .map(CredentialOfferStatusKey::getIndex)
                .collect(Collectors.toSet());
        assertThat(suspendedIndexes)
                .as("Suspendend and unsuspended should be the same indexes")
                .containsExactlyInAnyOrderElementsOf(unsuspendedIndexes);


        statusList = assertDoesNotThrow(() -> statusListRepository.findById(statusListId).orElseThrow());
        tokenStatusList = TokenStatusListToken.loadTokenStatusListToken((Integer) statusList.getConfig().get("bits"), statusList.getStatusZipped(), 204800);
        for (var offerStatus : issuedOfferStatus) {
            assertThat(tokenStatusList.getStatus(offerStatus.getId().getIndex())).as("VC has been unsuspended").isZero();
        }
        for (var offerStatus : revokedOfferStatus) {
            assertThat(tokenStatusList.getStatus(offerStatus.getId().getIndex())).as("VC has been still revoked").isEqualTo(1);
        }
        for (Integer index : unusedIndexes) {
            assertThat(tokenStatusList.getStatus(index)).as("Index is still unused / valid").isZero();
        }
    }

    private CredentialWithDeeplinkResponseDto prepareIssuedCredential() throws Exception {
        var createRequestBody = objectMapper.writeValueAsString(CreateCredentialOfferRequestDto.builder()
                .metadataCredentialSupportedId(List.of("university_example_sd_jwt"))
                .credentialSubjectData(getUniversityCredentialSubjectData())
                .statusLists(List.of(statusListUri))
                .build());

        var createCredentialOfferResult = mvc.perform(post(CREDENTIAL_MANAGEMENT_BASE_URL).contentType(
                                MediaType.APPLICATION_JSON)
                        .content(createRequestBody))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse();

        var credentialWithDeeplinkResponseDto = objectMapper.readValue(createCredentialOfferResult.getContentAsString(), CredentialWithDeeplinkResponseDto.class);

        List<ECKey> holderPrivateKeys = IssuanceV2TestUtils.createHolderPrivateKeysV2(issuerMetadata.getIssuanceBatchSize());

        var token = IssuanceV2TestUtils.getAccessTokenFromDeeplink(mvc, credentialWithDeeplinkResponseDto.getOfferDeeplink());
        var credentialRequestString = IssuanceV2TestUtils.getCredentialRequestStringV2(mvc, holderPrivateKeys, applicationProperties);

        IssuanceV2TestUtils.requestCredentialV2(mvc, token, credentialRequestString)
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        return credentialWithDeeplinkResponseDto;
    }

    private void changeCredentialManagementStatus(UUID managementId, CredentialStatusTypeDto newStatus) throws Exception {
        mvc.perform(patch(getUpdateUrl(managementId, newStatus)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value(newStatus.toString()));
    }

    // todo fix
    private String getUpdateUrl(UUID id, CredentialStatusTypeDto credentialStatus) {
        return String.format("%s/%s/status?credentialStatus=%s", CREDENTIAL_MANAGEMENT_BASE_URL, id, credentialStatus);
    }
}