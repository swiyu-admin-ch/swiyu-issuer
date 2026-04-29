package ch.admin.bj.swiyu.issuer.oid4vci.service;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.domain.callback.CallbackEvent;
import ch.admin.bj.swiyu.issuer.domain.callback.CallbackEventRepository;
import ch.admin.bj.swiyu.issuer.domain.callback.CallbackEventTrigger;
import ch.admin.bj.swiyu.issuer.domain.callback.CallbackEventType;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialManagement;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialManagementRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusManagementType;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusList;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusListRepository;
import ch.admin.bj.swiyu.issuer.dto.callback.CallbackErrorEventTypeDto;
import ch.admin.bj.swiyu.issuer.dto.credentialofferstatus.UpdateCredentialStatusRequestTypeDto;
import ch.admin.bj.swiyu.issuer.service.statuslist.StatusListPersistenceService;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

import static ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller.IssuanceTestUtils.updateStatus;
import static ch.admin.bj.swiyu.issuer.oid4vci.test.CredentialOfferTestData.createStatusList;
import static ch.admin.bj.swiyu.issuer.oid4vci.test.CredentialOfferTestData.createTestOffer;
import static ch.admin.bj.swiyu.issuer.oid4vci.test.CredentialOfferTestData.linkStatusList;
import static ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusType.ISSUED;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration test verifying the {@code @TransactionalEventListener} webhook behaviour
 * when a status list update succeeds or fails during a credential management state transition.
 *
 * <h2>Background</h2>
 * <p>When a REVOKE or SUSPEND is requested, the Spring State Machine executes two actions
 * within the same {@code @Transactional} boundary:
 * <ol>
 *   <li>{@code eventActions.managementStateChangeAction()} – publishes a
 *       {@code ManagementStateChangeEvent} into the Spring transaction synchronisation buffer.</li>
 *   <li>{@code managementActions.revokeAction()} / {@code suspendAction()} – writes the updated
 *       status bits to the status list.</li>
 * </ol>
 *
 * <h2>Happy path (AFTER_COMMIT)</h2>
 * <p>When the status list update succeeds, the transaction commits and Spring delivers the
 * buffered event to
 * {@link ch.admin.bj.swiyu.issuer.service.webhook.AsyncCredentialEventHandler#handleManagementStateChangeEvent},
 * which persists a {@code VC_STATUS_CHANGED} {@link ch.admin.bj.swiyu.issuer.domain.callback.CallbackEvent}.
 *
 * <h2>Failure path (AFTER_ROLLBACK)</h2>
 * <p>When the status list update throws, the transaction rolls back. Spring delivers the
 * buffered event instead to
 * {@link ch.admin.bj.swiyu.issuer.service.webhook.AsyncCredentialEventHandler#handleManagementStateChangeRollback},
 * which persists an {@code ERROR} {@link ch.admin.bj.swiyu.issuer.domain.callback.CallbackEvent}
 * with error code {@code STATUS_LIST_UPDATE_FAILED} – so the Business Issuer is informed
 * that the state change did <em>not</em> take effect.
 *
 * <h2>Test setup</h2>
 * <p>{@link ch.admin.bj.swiyu.issuer.service.statuslist.StatusListPersistenceService} is replaced
 * with a {@code @MockitoBean} to avoid the {@code @Transactional(MANDATORY)} constraint on
 * {@code revoke()} / {@code suspend()} when stubbing. In the happy-path tests the mock simply
 * returns an empty list; in the failure-path tests it is configured to throw.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
class StatusListWebhookIT {

    @Autowired
    private MockMvc mock;

    @Autowired
    private StatusListRepository statusListRepository;

    @Autowired
    private CredentialOfferRepository credentialOfferRepository;

    @Autowired
    private CredentialOfferStatusRepository credentialOfferStatusRepository;

    @Autowired
    private CredentialManagementRepository credentialManagementRepository;

    @Autowired
    private CallbackEventRepository callbackEventRepository;

    @DynamicPropertySource
    static void webhookProperties(DynamicPropertyRegistry registry) {
        // A non-blank callback-uri is required so that WebhookEventProducer.createEvent()
        // does not short-circuit and actually persists the CallbackEvent.
        registry.add("webhook.callback-uri", () -> "http://localhost/callback");
    }

    @MockitoBean
    private StatusListPersistenceService statusListPersistenceService;

    private StatusList testStatusList;
    private CredentialManagement issuedManagement;

    @BeforeEach
    void setUp() {
        callbackEventRepository.deleteAll();
        credentialOfferStatusRepository.deleteAll();
        credentialOfferRepository.deleteAll();
        credentialManagementRepository.deleteAll();
        statusListRepository.deleteAll();

        doReturn(List.of()).when(statusListPersistenceService).revoke(any());
        doReturn(List.of()).when(statusListPersistenceService).suspend(any());
        doReturn(List.of()).when(statusListPersistenceService).revalidate(any());

        testStatusList = statusListRepository.save(createStatusList());
        issuedManagement = createIssuedCredentialManagement();
    }

    @Test
    void whenRevokeSucceeds_thenVcStatusChangedEventPersistedAndNoErrorEvent() throws Exception {
        updateStatus(mock, issuedManagement.getId().toString(), UpdateCredentialStatusRequestTypeDto.REVOKED)
                .andExpect(status().isOk());

        var events = awaitCallbackEvents(1);

        assertThat(events).hasSize(1);
        var event = events.getFirst();
        assertThat(event.getType()).isEqualTo(CallbackEventType.VC_STATUS_CHANGED);
        assertThat(event.getEvent()).isEqualTo(CredentialStatusManagementType.REVOKED.name());
        assertThat(event.getEventTrigger()).isEqualTo(CallbackEventTrigger.CREDENTIAL_MANAGEMENT);
        assertThat(event.getSubjectId()).isEqualTo(issuedManagement.getId());
    }

    /**
     * Verifies the failure path for REVOKE:
     * when {@code StatusListPersistenceService.revoke()} throws, the transaction rolls back,
     * the {@code AFTER_COMMIT} listener is suppressed, and the {@code AFTER_ROLLBACK} listener
     * persists exactly one {@code ERROR} event with {@code STATUS_LIST_UPDATE_FAILED}.
     * No {@code VC_STATUS_CHANGED} event must be present.
     */
    @Test
    void whenRevokeFailsDueToStatusListError_thenNoVcStatusChangedEventAndErrorEventPersisted() throws Exception {
        doThrow(new RuntimeException("Status registry unavailable"))
                .when(statusListPersistenceService).revoke(any());

        updateStatus(mock, issuedManagement.getId().toString(), UpdateCredentialStatusRequestTypeDto.REVOKED)
                .andExpect(status().is4xxClientError());

        var events = awaitCallbackEvents(1);

        assertThat(events).hasSize(1);
        var event = events.getFirst();
        assertThat(event.getType()).isEqualTo(CallbackEventType.ERROR);
        assertThat(event.getEvent()).isEqualTo(CallbackErrorEventTypeDto.STATUS_LIST_UPDATE_FAILED.name());
        assertThat(event.getEventTrigger()).isEqualTo(CallbackEventTrigger.CREDENTIAL_MANAGEMENT);
        assertThat(event.getSubjectId()).isEqualTo(issuedManagement.getId());
        assertThat(events).noneMatch(e -> e.getType() == CallbackEventType.VC_STATUS_CHANGED);
    }

    /**
     * Verifies the failure path for SUSPEND:
     * when {@code StatusListPersistenceService.suspend()} throws, the transaction rolls back,
     * the {@code AFTER_COMMIT} listener is suppressed, and the {@code AFTER_ROLLBACK} listener
     * persists exactly one {@code ERROR} event with {@code STATUS_LIST_UPDATE_FAILED}.
     * No {@code VC_STATUS_CHANGED} event must be present.
     */
    @Test
    void whenSuspendFailsDueToStatusListError_thenNoVcStatusChangedEventAndErrorEventPersisted() throws Exception {
        doThrow(new RuntimeException("Status registry unavailable"))
                .when(statusListPersistenceService).suspend(any());

        updateStatus(mock, issuedManagement.getId().toString(), UpdateCredentialStatusRequestTypeDto.SUSPENDED)
                .andExpect(status().is4xxClientError());

        var events = awaitCallbackEvents(1);

        assertThat(events).hasSize(1);
        var event = events.getFirst();
        assertThat(event.getType()).isEqualTo(CallbackEventType.ERROR);
        assertThat(event.getEvent()).isEqualTo(CallbackErrorEventTypeDto.STATUS_LIST_UPDATE_FAILED.name());
        assertThat(event.getEventTrigger()).isEqualTo(CallbackEventTrigger.CREDENTIAL_MANAGEMENT);
        assertThat(event.getSubjectId()).isEqualTo(issuedManagement.getId());
        assertThat(events).noneMatch(e -> e.getType() == CallbackEventType.VC_STATUS_CHANGED);
    }

    /**
     * Polls until at least {@code expectedCount} CallbackEvents are present in the database,
     * waiting at most 5 seconds. Required because the handler runs on a separate thread via {@code @Async}.
     */
    private List<CallbackEvent> awaitCallbackEvents(int expectedCount) {
        Awaitility.await()
                .atMost(Duration.ofSeconds(5))
                .pollInterval(Duration.ofMillis(100))
                .until(() -> findAllCallbackEvents().size() >= expectedCount);
        return findAllCallbackEvents();
    }

    /**
     * Reads all callback events without a pessimistic write lock.
     * {@link CallbackEventRepository#findAll()} uses {@code PESSIMISTIC_WRITE} which requires an
     * active read-write transaction – not available in a plain test method context.
     * {@link CallbackEventRepository#findAllByTimestampBefore(java.time.Instant)} has no lock
     * and is therefore safe to call here.
     */
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

