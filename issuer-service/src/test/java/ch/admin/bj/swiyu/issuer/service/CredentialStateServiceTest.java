package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.UpdateStatusResponseDto;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.service.persistence.CredentialPersistenceService;
import ch.admin.bj.swiyu.issuer.service.statuslist.StatusListPersistenceService;
import ch.admin.bj.swiyu.issuer.service.webhook.OfferStateChangeEvent;
import ch.admin.bj.swiyu.issuer.service.webhook.StateChangeEvent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.context.ApplicationEventPublisher;

import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class CredentialStateServiceTest {

    @Mock
    private CredentialStateMachine credentialStateMachine;

    @Mock
    private ApplicationEventPublisher applicationEventPublisher;

    @Mock
    private CredentialPersistenceService persistenceService;

    @Mock
    private StatusListPersistenceService statusListPersistenceService;

    private CredentialStateService stateService;

    private AutoCloseable mocks;

    @BeforeEach
    void setUp() {
        mocks = MockitoAnnotations.openMocks(this);
        stateService = new CredentialStateService(
                credentialStateMachine,
                applicationEventPublisher,
                persistenceService,
                statusListPersistenceService);
    }

    @AfterEach
    void tearDown() throws Exception {
        if (mocks != null) {
            mocks.close();
        }
    }

    /**
     * Happy path: when the offer state changes, the service must publish an {@link OfferStateChangeEvent}.
     */
    @Test
    void updateOfferStateAndPublish_shouldPublishEventWhenStateChanged() {
        var offerId = UUID.randomUUID();
        var offer = CredentialOffer.builder()
                .id(offerId)
                .credentialStatus(CredentialOfferStatusType.OFFERED)
                .build();
        var mgmtId = UUID.randomUUID();

        var result = new CredentialStateMachine.StateTransitionResult<CredentialOfferStatusType>(
                CredentialOfferStatusType.READY,
                true);

        when(credentialStateMachine.sendEventAndUpdateStatus(eq(offer), eq(CredentialStateMachineConfig.CredentialOfferEvent.READY)))
                .thenReturn(result);

        var actual = stateService.updateOfferStateAndPublish(
                offer, CredentialStateMachineConfig.CredentialOfferEvent.READY);

        assertSame(result, actual);

        var eventCaptor = org.mockito.ArgumentCaptor.forClass(Object.class);
        verify(applicationEventPublisher, times(1)).publishEvent(eventCaptor.capture());
        assertInstanceOf(OfferStateChangeEvent.class, eventCaptor.getValue());
        var evt = (OfferStateChangeEvent) eventCaptor.getValue();
        assertEquals(offerId, evt.credentialOfferId());
        assertEquals(CredentialOfferStatusType.READY, evt.newState());
    }

    /**
     * Edge case: when the state machine reports no state change, no event must be published.
     */
    @Test
    void updateOfferStateAndPublish_shouldNotPublishEventWhenStateUnchanged() {
        var offer = CredentialOffer.builder()
                .id(UUID.randomUUID())
                .credentialStatus(CredentialOfferStatusType.OFFERED)
                .build();

        when(credentialStateMachine.sendEventAndUpdateStatus(eq(offer), any()))
                .thenReturn(new CredentialStateMachine.StateTransitionResult<CredentialOfferStatusType>(CredentialOfferStatusType.OFFERED, false));

        var result = stateService.updateOfferStateAndPublish(
                offer, CredentialStateMachineConfig.CredentialOfferEvent.CLAIM);

        assertFalse(result.changed());
        verifyNoInteractions(applicationEventPublisher);
    }

    /**
     * Happy path: when the management state changes, the service must publish a {@link StateChangeEvent}.
     */
    @Test
    void updateManagementStateAndPublish_shouldPublishEventWhenStateChanged() {
        var mgmtId = UUID.randomUUID();
        var mgmt = CredentialManagement.builder()
                .id(mgmtId)
                .credentialManagementStatus(CredentialStatusManagementType.INIT)
                .build();

        when(credentialStateMachine.sendEventAndUpdateStatus(eq(mgmt), eq(CredentialStateMachineConfig.CredentialManagementEvent.ISSUE)))
                .thenReturn(new CredentialStateMachine.StateTransitionResult<CredentialStatusManagementType>(CredentialStatusManagementType.ISSUED, true));

        var result = stateService.updateManagementStateAndPublish(
                mgmt, CredentialStateMachineConfig.CredentialManagementEvent.ISSUE);

        assertTrue(result.changed());

        var eventCaptor = org.mockito.ArgumentCaptor.forClass(Object.class);
        verify(applicationEventPublisher).publishEvent(eventCaptor.capture());
        assertInstanceOf(StateChangeEvent.class, eventCaptor.getValue());
        var evt = (StateChangeEvent) eventCaptor.getValue();
        assertEquals(mgmtId, evt.credentialOfferId());
        assertEquals(CredentialStatusManagementType.ISSUED, evt.newState());
    }

    /**
     * Edge case: when the management state does not change, no event must be published.
     */
    @Test
    void updateManagementStateAndPublish_shouldNotPublishEventWhenStateUnchanged() {
        var mgmt = CredentialManagement.builder()
                .id(UUID.randomUUID())
                .credentialManagementStatus(CredentialStatusManagementType.ISSUED)
                .build();

        when(credentialStateMachine.sendEventAndUpdateStatus(eq(mgmt), any()))
                .thenReturn(new CredentialStateMachine.StateTransitionResult<CredentialStatusManagementType>(CredentialStatusManagementType.ISSUED, false));

        var result = stateService.updateManagementStateAndPublish(
                mgmt, CredentialStateMachineConfig.CredentialManagementEvent.SUSPEND);

        assertFalse(result.changed());
        verifyNoInteractions(applicationEventPublisher);
    }

    /**
     * Happy path: pre-issuance must update the offer first (leading) and then the management.
     */
    @Test
    void handlePreIssuanceStateTransition_shouldUpdateOfferFirstThenManagement() {
        var mgmt = CredentialManagement.builder().id(UUID.randomUUID()).build();
        var offer = CredentialOffer.builder().id(UUID.randomUUID()).credentialManagement(mgmt).build();

        when(credentialStateMachine.sendEventAndUpdateStatus(eq(offer), eq(CredentialStateMachineConfig.CredentialOfferEvent.CLAIM)))
                .thenReturn(new CredentialStateMachine.StateTransitionResult<CredentialOfferStatusType>(CredentialOfferStatusType.IN_PROGRESS, true));

        var inOrder = inOrder(credentialStateMachine);

        var result = stateService.handlePreIssuanceStateTransition(
                mgmt,
                offer,
                CredentialStateMachineConfig.CredentialManagementEvent.ISSUE,
                CredentialStateMachineConfig.CredentialOfferEvent.CLAIM);

        assertTrue(result.changed());
        assertEquals(CredentialOfferStatusType.IN_PROGRESS, result.newStatus());

        inOrder.verify(credentialStateMachine).sendEventAndUpdateStatus(eq(offer), eq(CredentialStateMachineConfig.CredentialOfferEvent.CLAIM));
        inOrder.verify(credentialStateMachine).sendEventAndUpdateStatus(eq(mgmt), eq(CredentialStateMachineConfig.CredentialManagementEvent.ISSUE));
    }

    /**
     * Happy path: post-issuance must update the management first (leading) and then the offer.
     */
    @Test
    void handlePostIssuanceStateTransition_shouldUpdateManagementFirstThenOffer() {
        var mgmt = CredentialManagement.builder().id(UUID.randomUUID()).build();
        var offer = CredentialOffer.builder().id(UUID.randomUUID()).credentialManagement(mgmt).build();

        when(credentialStateMachine.sendEventAndUpdateStatus(eq(mgmt), eq(CredentialStateMachineConfig.CredentialManagementEvent.SUSPEND)))
                .thenReturn(new CredentialStateMachine.StateTransitionResult<CredentialStatusManagementType>(CredentialStatusManagementType.SUSPENDED, true));

        var inOrder = inOrder(credentialStateMachine);

        var result = stateService.handlePostIssuanceStateTransition(
                mgmt,
                offer,
                CredentialStateMachineConfig.CredentialManagementEvent.SUSPEND,
                CredentialStateMachineConfig.CredentialOfferEvent.CANCEL);

        assertTrue(result.changed());
        assertEquals(CredentialStatusManagementType.SUSPENDED, result.newStatus());

        inOrder.verify(credentialStateMachine).sendEventAndUpdateStatus(eq(mgmt), eq(CredentialStateMachineConfig.CredentialManagementEvent.SUSPEND));
        inOrder.verify(credentialStateMachine).sendEventAndUpdateStatus(eq(offer), eq(CredentialStateMachineConfig.CredentialOfferEvent.CANCEL));
    }

    /**
     * Happy path: expiring an offer must send EXPIRE to the state machine and publish an offer state change event.
     */
    @Test
    void expireOfferAndPublish_shouldExpireAndPublishEvent() {
        var mgmt = CredentialManagement.builder().id(UUID.randomUUID()).build();
        var offerId = UUID.randomUUID();
        var offer = CredentialOffer.builder()
                .id(offerId)
                .credentialManagement(mgmt)
                .credentialStatus(CredentialOfferStatusType.OFFERED)
                .build();

        doAnswer(invocation -> {
            // simulate that state machine updates the offer status
            offer.setCredentialOfferStatusJustForTestUsage(CredentialOfferStatusType.EXPIRED);
            return null;
        }).when(credentialStateMachine)
                .sendEventAndUpdateStatus(eq(offer), eq(CredentialStateMachineConfig.CredentialOfferEvent.EXPIRE));

        stateService.expireOfferAndPublish(offer);

        verify(credentialStateMachine, times(1)).sendEventAndUpdateStatus(
                eq(offer), eq(CredentialStateMachineConfig.CredentialOfferEvent.EXPIRE));

        var eventCaptor = org.mockito.ArgumentCaptor.forClass(Object.class);
        verify(applicationEventPublisher, times(1)).publishEvent(eventCaptor.capture());
        assertInstanceOf(OfferStateChangeEvent.class, eventCaptor.getValue());
        var evt = (OfferStateChangeEvent) eventCaptor.getValue();
        assertEquals(offerId, evt.credentialOfferId());
        assertEquals(CredentialOfferStatusType.EXPIRED, evt.newState());
    }

    /**
     * Happy path: marking an offer as ready should send READY to the state machine.
     */
    @Test
    void markOfferAsReady_shouldUpdateState() {
        var offer = CredentialOffer.builder()
                .id(UUID.randomUUID())
                .credentialStatus(CredentialOfferStatusType.DEFERRED)
                .build();

        stateService.markOfferAsReady(offer);

        verify(credentialStateMachine, times(1)).sendEventAndUpdateStatus(
                eq(offer), eq(CredentialStateMachineConfig.CredentialOfferEvent.READY));
        verifyNoInteractions(applicationEventPublisher);
    }

    /**
     * Happy path: in pre-issuance, if the offer state changes, the updated offer must be persisted.
     */
    @Test
    void handleStatusChangeForPreIssuanceProcess_shouldPersistOfferWhenOfferChanged() {
        var mgmt = CredentialManagement.builder().id(UUID.randomUUID()).credentialManagementStatus(CredentialStatusManagementType.INIT).build();
        var offer = CredentialOffer.builder().id(UUID.randomUUID()).credentialManagement(mgmt).build();

        when(credentialStateMachine.sendEventAndUpdateStatus(eq(offer), any()))
                .thenReturn(new CredentialStateMachine.StateTransitionResult<CredentialOfferStatusType>(CredentialOfferStatusType.OFFERED, true));

        var response = stateService.handleStatusChangeForPreIssuanceProcess(
                mgmt,
                offer,
                CredentialStateMachineConfig.CredentialManagementEvent.ISSUE,
                CredentialStateMachineConfig.CredentialOfferEvent.CLAIM);

        assertNotNull(response);
        verify(persistenceService).saveCredentialOffer(eq(offer));
    }

    /**
     * Edge case: in pre-issuance, if the offer state does not change, the offer must not be persisted.
     */
    @Test
    void handleStatusChangeForPreIssuanceProcess_shouldNotPersistOfferWhenOfferUnchanged() {
        var mgmt = CredentialManagement.builder().id(UUID.randomUUID()).credentialManagementStatus(CredentialStatusManagementType.INIT).build();
        var offer = CredentialOffer.builder().id(UUID.randomUUID()).credentialManagement(mgmt).build();

        when(credentialStateMachine.sendEventAndUpdateStatus(eq(offer), any()))
                .thenReturn(new CredentialStateMachine.StateTransitionResult<CredentialOfferStatusType>(CredentialOfferStatusType.OFFERED, false));

        var response = stateService.handleStatusChangeForPreIssuanceProcess(
                mgmt,
                offer,
                CredentialStateMachineConfig.CredentialManagementEvent.ISSUE,
                CredentialStateMachineConfig.CredentialOfferEvent.CLAIM);

        assertNotNull(response);
        verify(persistenceService, never()).saveCredentialOffer(any());
    }

    /**
     * Happy path: post-issuance status change triggers status list update + management persistence.
     */
    @Test
    void handleStatusChangeForPostIssuanceProcess_shouldUpdateStatusListsAndPersistManagementWhenChanged() {
        var offer1 = CredentialOffer.builder().id(UUID.randomUUID()).credentialStatus(CredentialOfferStatusType.ISSUED).build();
        var offer2 = CredentialOffer.builder().id(UUID.randomUUID()).credentialStatus(CredentialOfferStatusType.REQUESTED).build();

        var mgmt = CredentialManagement.builder()
                .id(UUID.randomUUID())
                .credentialOffers(Set.of(offer1, offer2))
                .credentialManagementStatus(CredentialStatusManagementType.ISSUED)
                .build();

        when(credentialStateMachine.sendEventAndUpdateStatus(eq(mgmt), any()))
                .thenReturn(new CredentialStateMachine.StateTransitionResult<CredentialStatusManagementType>(CredentialStatusManagementType.REVOKED, true));

        when(credentialStateMachine.sendEventAndUpdateStatus(any(CredentialOffer.class), any()))
                .thenReturn(new CredentialStateMachine.StateTransitionResult<CredentialOfferStatusType>(CredentialOfferStatusType.OFFERED, true));

        var persistedStatuses = Set.<CredentialOfferStatus>of(
                CredentialOfferStatus.builder()
                        .id(CredentialOfferStatusKey.builder()
                                .offerId(offer1.getId())
                                .statusListId(UUID.randomUUID())
                                .index(1)
                                .build())
                        .build());

        when(persistenceService.findCredentialOfferStatusesByOfferIds(eq(List.of(offer1.getId(), offer2.getId()))))
                .thenReturn(persistedStatuses);

        var expectedStatusListIds = List.of(UUID.randomUUID());
        when(statusListPersistenceService.revoke(eq(persistedStatuses)))
                .thenReturn(expectedStatusListIds);

        when(persistenceService.saveCredentialManagement(eq(mgmt))).thenReturn(mgmt);

        UpdateStatusResponseDto response = stateService.handleStatusChangeForPostIssuanceProcess(
                mgmt,
                offer1,
                CredentialStateMachineConfig.CredentialManagementEvent.REVOKE,
                CredentialStateMachineConfig.CredentialOfferEvent.CANCEL);

        assertNotNull(response);

        verify(statusListPersistenceService).revoke(anySet());
        verify(persistenceService).saveCredentialManagement(eq(mgmt));
    }

}
