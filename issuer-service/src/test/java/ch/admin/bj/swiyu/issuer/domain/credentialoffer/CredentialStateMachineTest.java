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

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class CredentialStateMachineTest {
    private EventProducerService eventProducerService;
    private CredentialStateMachine stateMachine;

    @BeforeEach
    void setUp() {
        this.eventProducerService = mock(EventProducerService.class);
        CredentialPersistenceService credentialPersistenceService = mock(CredentialPersistenceService.class);
        StatusListPersistenceService statusListPersistanceService = mock(StatusListPersistenceService.class);
        EventProducerAction eventActions = new EventProducerAction(eventProducerService);
        CredentialManagementAction managementActions = new CredentialManagementAction(credentialPersistenceService, statusListPersistanceService);
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

}
