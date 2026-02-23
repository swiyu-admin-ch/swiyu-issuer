package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.dto.credentialofferstatus.UpdateStatusResponseDto;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.service.persistence.CredentialPersistenceService;
import ch.admin.bj.swiyu.issuer.service.statuslist.StatusListPersistenceService;
import ch.admin.bj.swiyu.issuer.service.webhook.OfferStateChangeEvent;
import ch.admin.bj.swiyu.issuer.service.webhook.ManagementStateChangeEvent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.context.ApplicationEventPublisher;

import java.util.List;
import java.util.Random;
import java.util.UUID;
import java.util.stream.Collectors;

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

    private static final Random rand = new Random();

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
     * Happy path: post-issuance status change triggers status list update + management persistence.
     */
    @Test
    void handleStatusChangeForPostIssuanceProcess_shouldUpdateStatusListsAndPersistManagementWhenChanged() {
        var offers = List.of(CredentialOfferStatusType.ISSUED, CredentialOfferStatusType.ISSUED, CredentialOfferStatusType.EXPIRED, CredentialOfferStatusType.CANCELLED, CredentialOfferStatusType.REQUESTED)
                .stream().map(state -> CredentialOffer.builder().id(UUID.randomUUID()).credentialStatus(state).build())
                .collect(Collectors.toSet());

        var mgmt = CredentialManagement.builder()
                .id(UUID.randomUUID())
                .credentialOffers(offers)
                .credentialManagementStatus(CredentialStatusManagementType.ISSUED)
                .build();

        when(credentialStateMachine.sendEventAndUpdateStatus(eq(mgmt), any()))
                .thenReturn(new CredentialStateMachine.StateTransitionResult<CredentialStatusManagementType>(CredentialStatusManagementType.REVOKED, true));

        when(credentialStateMachine.sendEventAndUpdateStatus(any(CredentialOffer.class), any()))
                .thenReturn(new CredentialStateMachine.StateTransitionResult<CredentialOfferStatusType>(CredentialOfferStatusType.OFFERED, true));

        var persistedStatuses = offers.stream().map(offer -> CredentialOfferStatus.builder()
                        .id(CredentialOfferStatusKey.builder()
                        .offerId(offer.getId())
                        .statusListId(UUID.randomUUID())
                        .index(rand.nextInt(10000))
                        .build()).build())
                .collect(Collectors.toSet());

        var offerIds = offers.stream().map(CredentialOffer::getId).toList();
        when(persistenceService.findCredentialOfferStatusesByOfferIds(eq(offerIds)))
                .thenReturn(persistedStatuses);

        var expectedStatusListIds = List.of(UUID.randomUUID());
        when(statusListPersistenceService.revoke(eq(persistedStatuses)))
                .thenReturn(expectedStatusListIds);

        when(persistenceService.saveCredentialManagement(eq(mgmt))).thenReturn(mgmt);

        UpdateStatusResponseDto response = stateService.handleStatusChange(
                mgmt,
                CredentialStateMachineConfig.CredentialManagementEvent.REVOKE,
                CredentialStateMachineConfig.CredentialOfferEvent.CANCEL);

        assertNotNull(response);
        verify(statusListPersistenceService).revoke(eq(persistedStatuses));
        verify(persistenceService).saveCredentialManagement(eq(mgmt));
    }

}
