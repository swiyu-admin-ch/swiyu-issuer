package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

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
    private CredentialStateMachineAction actions;
    private CredentialStateMachine stateMachine;

    @BeforeEach
    void setUp() {
        this.eventProducerService = mock(EventProducerService.class);
        this.actions = new CredentialStateMachineAction(this.eventProducerService);
        var config = new CredentialStateMachineConfig(this.actions);
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
