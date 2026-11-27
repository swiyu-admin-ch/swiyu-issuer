package ch.admin.bj.swiyu.issuer.oid4vci.service;

import ch.admin.bj.swiyu.core.status.registry.client.api.StatusB2BV2Api;
import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.domain.callback.CallbackEvent;
import ch.admin.bj.swiyu.issuer.domain.callback.CallbackEventRepository;
import ch.admin.bj.swiyu.issuer.domain.callback.CallbackEventType;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialManagement;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialManagementRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusManagementType;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusList;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusListRepository;
import ch.admin.bj.swiyu.issuer.dto.credentialofferstatus.UpdateCredentialStatusRequestTypeDto;
import ch.admin.bj.swiyu.statuslist.TokenStatusList;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

import static ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusType.ISSUED;
import static ch.admin.bj.swiyu.issuer.oid4vci.infrastructure.web.controller.IssuanceTestUtils.updateStatus;
import static ch.admin.bj.swiyu.issuer.oid4vci.test.CredentialOfferTestData.createStatusList;
import static ch.admin.bj.swiyu.issuer.oid4vci.test.CredentialOfferTestData.createTestOffer;
import static ch.admin.bj.swiyu.issuer.oid4vci.test.CredentialOfferTestData.linkStatusList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for the consistency of credential status updates (REVOKE) between the local database and the
 * external status registry.
 *
 * <ul>
 *   <li>A registry failure must roll the local status change back and must not emit a success callback.</li>
 *   <li>A database write failure must abort the operation before the registry is updated, and must not emit a
 *       success callback.</li>
 * </ul>
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
class StatusListRegistryFailureIT {

    @Autowired
    private MockMvc mock;

    @MockitoSpyBean
    private StatusListRepository statusListRepository;

    @Autowired
    private CredentialOfferRepository credentialOfferRepository;

    @Autowired
    private CredentialOfferStatusRepository credentialOfferStatusRepository;

    @Autowired
    private CredentialManagementRepository credentialManagementRepository;

    @Autowired
    private CallbackEventRepository callbackEventRepository;

    @MockitoBean
    private StatusB2BV2Api statusB2BV2Api;

    private StatusList testStatusList;
    private CredentialManagement issuedManagement;

    @DynamicPropertySource
    static void webhookProperties(DynamicPropertyRegistry registry) {
        registry.add("webhook.callback-uri", () -> "http://localhost/callback");
    }

    @BeforeEach
    void setUp() throws IOException {
        reset(statusListRepository);

        callbackEventRepository.deleteAll();
        credentialOfferStatusRepository.deleteAll();
        credentialOfferRepository.deleteAll();
        credentialManagementRepository.deleteAll();
        statusListRepository.deleteAll();

        testStatusList = statusListRepository.save(createStatusList());
        issuedManagement = createIssuedCredentialManagement();
    }

    @Test
    void givenRegistryUpdateFails_whenRevoking_thenLocalStatusIsRolledBackAndNoSuccessCallbackIsEmitted() throws Exception {
        doThrow(new RuntimeException("registry unavailable"))
                .when(statusB2BV2Api).updateStatusListEntry(any(), any(), any());

        updateStatus(mock, issuedManagement.getId().toString(), UpdateCredentialStatusRequestTypeDto.REVOKED)
                .andExpect(status().is4xxClientError());

        assertLocalStatusIsStillIssued();
        assertNoSuccessCallbackWasEmitted();
    }

    @Test
    void givenDatabaseWriteFails_whenRevoking_thenRegistryIsNotUpdatedAndNoSuccessCallbackIsEmitted() throws Exception {
        doThrow(new RuntimeException("database unavailable"))
                .when(statusListRepository).saveAllAndFlush(anyList());

        updateStatus(mock, issuedManagement.getId().toString(), UpdateCredentialStatusRequestTypeDto.REVOKED)
                .andExpect(status().is4xxClientError());

        verify(statusB2BV2Api, never()).updateStatusListEntry(any(), any(), any());
        assertLocalStatusIsStillIssued();
        assertNoSuccessCallbackWasEmitted();
    }

    private void assertLocalStatusIsStillIssued() throws IOException {
        var reloadedManagement = credentialManagementRepository.findById(issuedManagement.getId()).orElseThrow();
        assertThat(reloadedManagement.getCredentialManagementStatus())
                .isEqualTo(CredentialStatusManagementType.ISSUED);

        var statusList = statusListRepository.findById(testStatusList.getId()).orElseThrow();
        var token = TokenStatusList.loadTokenStatusListToken(
                (Integer) statusList.getConfig().get("bits"), statusList.getStatusZipped(), 204800);
        assertThat(token.getStatus(0)).isZero();
    }

    private void assertNoSuccessCallbackWasEmitted() {
        var events = awaitCallbackEvents(1);
        assertThat(events).noneMatch(e -> e.getType() == CallbackEventType.VC_STATUS_CHANGED);
        assertThat(events).anyMatch(e -> e.getType() == CallbackEventType.ERROR);
    }

    private List<CallbackEvent> awaitCallbackEvents(int expectedCount) {
        Awaitility.await()
                .atMost(Duration.ofSeconds(5))
                .pollInterval(Duration.ofMillis(100))
                .until(() -> findAllCallbackEvents().size() >= expectedCount);
        return findAllCallbackEvents();
    }

    private List<CallbackEvent> findAllCallbackEvents() {
        return callbackEventRepository.findAllByTimestampBefore(Instant.now().plus(1, ChronoUnit.HOURS));
    }

    private CredentialManagement createIssuedCredentialManagement() {
        var management = credentialManagementRepository.save(CredentialManagement.builder()
                .id(UUID.randomUUID())
                .accessToken(UUID.randomUUID())
                .credentialManagementStatus(CredentialStatusManagementType.ISSUED)
                .accessTokenExpirationTimestamp(Instant.now().plusSeconds(120).getEpochSecond())
                .renewalRequestCnt(0)
                .renewalResponseCnt(0)
                .build());

        var offer = createTestOffer(UUID.randomUUID(), ISSUED, "university_example_sd_jwt");
        offer.setCredentialManagement(management);
        var savedOffer = credentialOfferRepository.save(offer);

        credentialOfferStatusRepository.save(linkStatusList(savedOffer, testStatusList, 0));

        management.addCredentialOffer(savedOffer);
        return credentialManagementRepository.save(management);
    }
}
