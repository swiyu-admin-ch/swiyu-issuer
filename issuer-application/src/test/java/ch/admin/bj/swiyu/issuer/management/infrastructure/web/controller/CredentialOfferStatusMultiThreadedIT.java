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
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.CredentialStatusTypeDto;
import ch.admin.bj.swiyu.issuer.common.config.SwiyuProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest()
@AutoConfigureMockMvc
@Testcontainers
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
@ActiveProfiles("test")
@Execution(ExecutionMode.SAME_THREAD)
class CredentialOfferStatusMultiThreadedIT {

    private final UUID statusListUUID = UUID.randomUUID();
    private final String statusRegistryUrl = "https://status-service-mock.bit.admin.ch/api/v1/statuslist/%s.jwt"
            .formatted(statusListUUID);

    @Autowired
    protected SwiyuProperties swiyuProperties;

    @Autowired
    protected MockMvc mvc;

    @Autowired
    private CredentialOfferRepository credentialOfferRepository;
    @Autowired
    private StatusListRepository statusListRepository;
    @Autowired
    private CredentialOfferStatusRepository credentialOfferStatusRepository;

    @MockitoBean
    private StatusBusinessApiApi statusBusinessApi;
    @Mock
    private ApiClient mockApiClient;

    private CredentialOfferTestHelper testHelper;

    @BeforeEach
    void setupTest() throws Exception {
        testHelper = new CredentialOfferTestHelper(mvc, credentialOfferRepository, credentialOfferStatusRepository, statusListRepository,
                statusRegistryUrl);

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
                                "{\"type\": \"TOKEN_STATUS_LIST\",\"maxLength\": 255,\"config\": {\"bits\": 2}}"))
                .andExpect(status().isOk());
    }

    @AfterEach
    void tearDown() {
        credentialOfferStatusRepository.deleteAll();
        credentialOfferRepository.deleteAll();
        statusListRepository.deleteAll();
    }


    @Test
    void testCreateOfferMultiThreaded_thenSuccess() {
        // create some offers in a multithreaded manner
        // When increasing this too much spring boot will throw 'Failed to read request'
        // in a non-deterministic way...
        var results = IntStream.range(0, 20).parallel().mapToObj(i -> {
            try {
                return testHelper.createStatusListLinkedOfferAndGetUUID();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }).toList();
        // Get unique indexed on status list
        var indexSet = credentialOfferRepository.findAllById(results).stream()
                .map(offer -> {
                            Set<CredentialOfferStatus> byOfferStatusId = credentialOfferStatusRepository.findByOfferStatusId(offer.getId());
                            return byOfferStatusId.stream().findFirst().get().getIndex();
                        }
                )
                .collect(Collectors.toSet());
        Assertions.assertThat(indexSet).as("Should be the same size if no status was used multiple times")
                .hasSameSizeAs(results);
    }

    @Test
    void testUpdateOfferStatusMultiThreaded_thenSuccess() throws Exception {
        // create some offers in a multithreaded manner
        // When increasing this too much spring boot will throw 'Failed to read request'
        // in a non-deterministic way...
        var offerIds = IntStream.range(0, 20).parallel().mapToObj(i -> {
            try {
                return testHelper.createStatusListLinkedOfferAndGetUUID();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }).toList();
        // Set offers to issued
        offerIds.forEach(offerId -> {
            testHelper.updateStatusForEntity(offerId, CredentialStatusType.ISSUED);
        });
        // Get all offers and the status list we are using
        var offers = offerIds.stream().map(credentialOfferRepository::findById).map(Optional::get).toList();
        CredentialOffer offer = offers.getFirst();
        Set<CredentialOfferStatus> credentialOfferStatuses = credentialOfferStatusRepository.findByOfferStatusId(offer.getId());
        var statusListId = credentialOfferStatuses.stream().findFirst().get().getId().getStatusListId();
        var statusListIndexes = offers.stream()
                .map(credentialOffer -> credentialOfferStatusRepository.findByOfferStatusId(credentialOffer.getId()))
                .flatMap(Set::stream).map(CredentialOfferStatus::getIndex).collect(Collectors.toSet());
        // Check initialization
        assertTrue(offerIds.stream().map(credentialOfferRepository::findById).allMatch(credentialOffer -> credentialOffer.get().getCredentialStatus() == CredentialStatusType.ISSUED));
        var initialStatusListToken = testHelper.loadTokenStatusListToken(2, statusListRepository.findById(statusListId).get().getStatusZipped());
        assertTrue(statusListIndexes.stream().allMatch(idx -> initialStatusListToken.getStatus(idx) == TokenStatusListBit.VALID.getValue()));
        // Update Status to Suspended
        offerIds.stream().parallel().forEach(offerId -> {
            try {
                mvc.perform(patch(testHelper.getUpdateUrl(offerId, CredentialStatusTypeDto.SUSPENDED)))
                        .andExpect(status().is(200));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        assertTrue(offerIds.stream().map(credentialOfferRepository::findById).allMatch(credentialOffer -> credentialOffer.get().getCredentialStatus() == CredentialStatusType.SUSPENDED));
        offerIds.forEach(testHelper::assertOfferStateConsistent);
        // Reset Status
        offerIds.stream().parallel().forEach(offerId -> {
            try {
                mvc.perform(patch(testHelper.getUpdateUrl(offerId, CredentialStatusTypeDto.ISSUED)))
                        .andExpect(status().is(200));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        assertTrue(offerIds.stream().map(credentialOfferRepository::findById).allMatch(credentialOffer -> credentialOffer.get().getCredentialStatus() == CredentialStatusType.ISSUED));
        offerIds.forEach(testHelper::assertOfferStateConsistent);
        var restoredStatusListToken = testHelper.loadTokenStatusListToken(2, statusListRepository.findById(statusListId).get().getStatusZipped());
        assertEquals(initialStatusListToken.getStatusListData(), restoredStatusListToken.getStatusListData(), "Bitstring should be same again");
    }
}