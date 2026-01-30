package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import ch.admin.bj.swiyu.issuer.service.webhook.EventProducerService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class CredentialOfferStateMachineTest {
    private CredentialStateMachine stateMachine;

    @BeforeEach
    void setUp() throws Exception {
        var eventProducerService = mock(EventProducerService.class);
        CredentialStateMachineAction actions = new CredentialStateMachineAction(eventProducerService);
        CredentialStateMachineConfig config = new CredentialStateMachineConfig(actions);
        this.stateMachine = new CredentialStateMachine(config.credentialManagementStateMachine(), config.credentialOfferStateMachine());
    }

    @Test
    void testOfferedToExpired() {
        var entitiy = new CredentialOffer();
        entitiy.setId(UUID.randomUUID());
        entitiy.setCredentialOfferStatus(CredentialOfferStatusType.REQUESTED);

        var result = stateMachine.sendEventAndUpdateStatus(entitiy, CredentialStateMachineConfig.CredentialOfferEvent.EXPIRE);
        assertTrue(result.changed());
        assertEquals(CredentialOfferStatusType.EXPIRED, entitiy.getCredentialStatus());
    }

    @Test
    void testInProgressToIssued() {
        var entitiy = new CredentialOffer();
        entitiy.setId(UUID.randomUUID());
        entitiy.setCredentialOfferStatus(CredentialOfferStatusType.IN_PROGRESS);

        var result = stateMachine.sendEventAndUpdateStatus(entitiy, CredentialStateMachineConfig.CredentialOfferEvent.ISSUE);
        assertTrue(result.changed());
        assertEquals(CredentialOfferStatusType.ISSUED, entitiy.getCredentialStatus());
    }

    @Test
    void testInvalidTransition() {
        var entitiy = new CredentialOffer();
        entitiy.setId(UUID.randomUUID());
        entitiy.setCredentialOfferStatus(CredentialOfferStatusType.EXPIRED);

        // invalid state transitions throw exception
        assertThrows(IllegalStateException.class, () -> stateMachine.sendEventAndUpdateStatus(entitiy, CredentialStateMachineConfig.CredentialOfferEvent.ISSUE));
        assertEquals(CredentialOfferStatusType.EXPIRED, entitiy.getCredentialStatus());
    }
}
