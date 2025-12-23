package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.statemachine.StateMachine;

import static org.junit.jupiter.api.Assertions.*;

class CredentialOfferStateMachineTest {
    private StateMachine<CredentialOfferStatusType, CredentialStateMachineConfig.CredentialOfferEvent> stateMachine;

    @BeforeEach
    void setUp() throws Exception {
        CredentialStateMachineConfig config = new CredentialStateMachineConfig();
        stateMachine = config.credentialOfferStateMachine();
        stateMachine.startReactively().block();
    }

    @Test
    void testOfferedToExpired() {
        stateMachine.getStateMachineAccessor().doWithAllRegions(access ->
            access.resetStateMachine(new org.springframework.statemachine.support.DefaultStateMachineContext<>(
                CredentialOfferStatusType.OFFERED, null, null, null)));
        stateMachine.startReactively().block();
        stateMachine.sendEvent(CredentialStateMachineConfig.CredentialOfferEvent.EXPIRE);
        assertEquals(CredentialOfferStatusType.EXPIRED, stateMachine.getState().getId());
    }

    @Test
    void testInProgressToIssued() {
        stateMachine.getStateMachineAccessor().doWithAllRegions(access ->
            access.resetStateMachine(new org.springframework.statemachine.support.DefaultStateMachineContext<>(
                CredentialOfferStatusType.IN_PROGRESS, null, null, null)));
        stateMachine.startReactively().block();
        stateMachine.sendEvent(CredentialStateMachineConfig.CredentialOfferEvent.ISSUE);
        assertEquals(CredentialOfferStatusType.ISSUED, stateMachine.getState().getId());
    }

    @Test
    void testDeferredToReadyToIssued() {
        stateMachine.getStateMachineAccessor().doWithAllRegions(access ->
            access.resetStateMachine(new org.springframework.statemachine.support.DefaultStateMachineContext<>(
                CredentialOfferStatusType.DEFERRED, null, null, null)));
        stateMachine.startReactively().block();
        stateMachine.sendEvent(CredentialStateMachineConfig.CredentialOfferEvent.READY);
        assertEquals(CredentialOfferStatusType.READY, stateMachine.getState().getId());
        stateMachine.sendEvent(CredentialStateMachineConfig.CredentialOfferEvent.ISSUE);
        assertEquals(CredentialOfferStatusType.ISSUED, stateMachine.getState().getId());
    }

    @Test
    void testInvalidTransition() {
        stateMachine.getStateMachineAccessor().doWithAllRegions(access ->
            access.resetStateMachine(new org.springframework.statemachine.support.DefaultStateMachineContext<>(
                CredentialOfferStatusType.EXPIRED, null, null, null)));
        stateMachine.startReactively().block();
        boolean result = stateMachine.sendEvent(CredentialStateMachineConfig.CredentialOfferEvent.ISSUE);
        assertFalse(result);
        assertEquals(CredentialOfferStatusType.EXPIRED, stateMachine.getState().getId());
    }
}
