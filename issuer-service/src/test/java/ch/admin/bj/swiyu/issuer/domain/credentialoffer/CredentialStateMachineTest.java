package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import ch.admin.bj.swiyu.issuer.domain.credentialoffer.statemachine.CredentialManagementAction;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.statemachine.CredentialOfferAction;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.statemachine.CredentialStateMachineConfig;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.statemachine.EventProducerAction;
import ch.admin.bj.swiyu.issuer.service.persistence.CredentialPersistenceService;
import ch.admin.bj.swiyu.issuer.service.statuslist.StatusListPersistenceService;
import ch.admin.bj.swiyu.issuer.service.webhook.EventProducerService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class CredentialStateMachineTest {
    private EventProducerService eventProducerService;
    private StatusListPersistenceService statusListPersistenceService;
    private CredentialStateMachine stateMachine;

    @BeforeEach
    void setUp() {
        this.eventProducerService = mock(EventProducerService.class);
        CredentialPersistenceService credentialPersistenceService = mock(CredentialPersistenceService.class);
        this.statusListPersistenceService = mock(StatusListPersistenceService.class);
        EventProducerAction eventActions = new EventProducerAction(eventProducerService);
        CredentialManagementAction managementActions = new CredentialManagementAction(credentialPersistenceService, statusListPersistenceService);
        CredentialOfferAction offerActions = new CredentialOfferAction();
        CredentialStateMachineConfig config = new CredentialStateMachineConfig(eventActions, offerActions, managementActions);
        this.stateMachine = new CredentialStateMachine(config.credentialManagementStateMachine(), config.credentialOfferStateMachine());
    }

    @Test
    void testWhenSendManagementStatusUpdate_thenCallChangeEventProducer() {
        var entity = new CredentialManagement();
        entity.setId(UUID.randomUUID());
        entity.setCredentialManagementStatus(CredentialStatusManagementType.INIT);

        var result = stateMachine.sendEventAndUpdateStatus(entity, CredentialStateMachineConfig.CredentialManagementEvent.ISSUE);
        assertTrue(result.changed());
        verify(eventProducerService).produceManagementStateChangeEvent(any(), any());
        assertEquals(CredentialStatusManagementType.ISSUED, entity.getCredentialManagementStatus());
    }

    @Test
    void testWhenSendOfferStatusUpdate_thenCallChangeEventProducer() {
        var entity = new CredentialOffer();
        entity.setId(UUID.randomUUID());
        entity.setCredentialOfferStatus(CredentialOfferStatusType.INIT);

        var result = stateMachine.sendEventAndUpdateStatus(entity, CredentialStateMachineConfig.CredentialOfferEvent.CREATED);
        assertTrue(result.changed());
        verify(eventProducerService).produceOfferStateChangeEvent(any(), any());
    }

    /**
     * Verifies that {@code eventActions.managementStateChangeAction()} is configured <em>before</em>
     * {@code managementActions.revokeAction()} in the state machine transition.
     *
     * <p>If the order were reversed, no event would be published when the status list update fails,
     * and Spring's {@code @TransactionalEventListener(AFTER_ROLLBACK)} would never fire – meaning
     * the Business Issuer would receive no error callback at all.
     *
     * <p>Note: the actual AFTER_COMMIT / AFTER_ROLLBACK routing is Spring infrastructure tested
     * in {@code StatusListWebhookIT}.
     */
    @Test
    void testWhenRevokeActionFails_thenManagementStateChangeEventWasStillPublished() {
        var entity = new CredentialManagement();
        entity.setId(UUID.randomUUID());
        entity.setCredentialManagementStatus(CredentialStatusManagementType.ISSUED);

        doThrow(new RuntimeException("Status list unavailable"))
                .when(statusListPersistenceService).revoke(any(Set.class));

        assertThrows(IllegalStateException.class, () ->
                stateMachine.sendEventAndUpdateStatus(entity, CredentialStateMachineConfig.CredentialManagementEvent.REVOKE));

        // The event must have been published before revokeAction() failed –
        // Spring will route it to @TransactionalEventListener(AFTER_ROLLBACK) at runtime.
        verify(eventProducerService).produceManagementStateChangeEvent(entity.getId(), CredentialStatusManagementType.REVOKED);
    }

    /**
     * Verifies that {@code eventActions.managementStateChangeAction()} is configured <em>before</em>
     * {@code managementActions.suspendAction()} in the state machine transition.
     *
     * <p>If the order were reversed, no event would be published when the status list update fails,
     * and Spring's {@code @TransactionalEventListener(AFTER_ROLLBACK)} would never fire – meaning
     * the Business Issuer would receive no error callback at all.
     *
     * <p>Note: the actual AFTER_COMMIT / AFTER_ROLLBACK routing is Spring infrastructure tested
     * in {@code StatusListWebhookIT}.
     */
    @Test
    void testWhenSuspendActionFails_thenManagementStateChangeEventWasStillPublished() {
        var entity = new CredentialManagement();
        entity.setId(UUID.randomUUID());
        entity.setCredentialManagementStatus(CredentialStatusManagementType.ISSUED);

        doThrow(new RuntimeException("Status list unavailable"))
                .when(statusListPersistenceService).suspend(any(Set.class));

        assertThrows(IllegalStateException.class, () ->
                stateMachine.sendEventAndUpdateStatus(entity, CredentialStateMachineConfig.CredentialManagementEvent.SUSPEND));

        verify(eventProducerService).produceManagementStateChangeEvent(entity.getId(), CredentialStatusManagementType.SUSPENDED);
    }

}
