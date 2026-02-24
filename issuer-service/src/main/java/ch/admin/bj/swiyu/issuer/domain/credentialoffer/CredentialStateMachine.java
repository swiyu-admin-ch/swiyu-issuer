package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import ch.admin.bj.swiyu.issuer.domain.credentialoffer.statemachine.CredentialStateMachineConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.statemachine.StateMachineEventResult;
import org.springframework.statemachine.support.DefaultStateMachineContext;
import org.springframework.stereotype.Service;
import org.springframework.statemachine.StateMachine;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
@Slf4j
public class CredentialStateMachine {
    private final StateMachine<CredentialStatusManagementType, CredentialStateMachineConfig.CredentialManagementEvent> credentialManagementStateMachine;
    private final StateMachine<CredentialOfferStatusType, CredentialStateMachineConfig.CredentialOfferEvent> credentialOfferStateMachine;


    /**
     * Send event to CredentialManagement state machine and update status.
     *
     * @param credentialManagement The CredentialManagement entity
     * @param event                The event to send
     * @return The result containing the new status and whether the state changed
     */
    public StateTransitionResult<CredentialStatusManagementType> sendEventAndUpdateStatus(
            CredentialManagement credentialManagement,
            CredentialStateMachineConfig.CredentialManagementEvent event) {

        if (event == null) {
            log.info("No transaction requested for {} in state {}", credentialManagement.getId(), credentialManagement.getCredentialManagementStatus());
            return new StateTransitionResult<>(credentialManagement.getCredentialManagementStatus(), false);
        }

        var oldStatus = credentialManagement.getCredentialManagementStatus();

        credentialManagementStateMachine.getStateMachineAccessor()
                .doWithAllRegions(access ->
                        access.resetStateMachineReactively(
                                new DefaultStateMachineContext<>(
                                        oldStatus,
                                        null,
                                        null,
                                        null
                                )
                        ).block()
                );

        StateMachineEventResult<CredentialStatusManagementType, CredentialStateMachineConfig.CredentialManagementEvent> stateMachineResult = credentialManagementStateMachine
                .sendEvent(
                        Mono.just(
                                MessageBuilder
                                        .withPayload(event)
                                        .setHeader("credentialId", credentialManagement.getId())
                                        .setHeader("oldStatus", oldStatus)
                                        .setHeader(CredentialStateMachineConfig.CREDENTIAL_MANAGEMENT_HEADER, credentialManagement)
                                        .build()
                        )
                )
                .blockLast();

        assert stateMachineResult != null;
        if (stateMachineResult.getResultType().equals(StateMachineEventResult.ResultType.ACCEPTED)) {
            var newStatus = credentialManagementStateMachine.getState().getId();
            credentialManagement.setCredentialManagementStatus(newStatus);
            boolean stateChanged = oldStatus != newStatus;
            log.info("Transaction accepted for: {}. New state = {} (changed: {})",
                    stateMachineResult.getMessage(), newStatus, stateChanged);
            return new StateTransitionResult<>(newStatus, stateChanged);
        } else {
            log.error("Transaction failed for: {}.", stateMachineResult.getMessage());
            throw new IllegalStateException("Transition failed for " + stateMachineResult.getMessage());
        }
    }

    /**
     * Send event to CredentialOffer state machine and update status.
     *
     * @param credentialOffer The CredentialOffer entity
     * @param event           The event to send
     * @return The result containing the new status and whether the state changed
     */
    public StateTransitionResult<CredentialOfferStatusType> sendEventAndUpdateStatus(
            CredentialOffer credentialOffer,
            CredentialStateMachineConfig.CredentialOfferEvent event) {

        if (event == null) {
            log.info("No transaction requested for {} in state {}", credentialOffer.getId(), credentialOffer.getCredentialStatus());
            return new StateTransitionResult<>(credentialOffer.getCredentialStatus(), false);
        }

        var oldStatus = credentialOffer.getCredentialStatus();

        credentialOfferStateMachine.getStateMachineAccessor()
                .doWithAllRegions(access ->
                        access.resetStateMachineReactively(
                                new DefaultStateMachineContext<>(
                                        oldStatus,
                                        null,
                                        null,
                                        null
                                )
                        ).block()
                );

        StateMachineEventResult<CredentialOfferStatusType, CredentialStateMachineConfig.CredentialOfferEvent> stateMachineResult = credentialOfferStateMachine
                .sendEvent(
                        Mono.just(
                                MessageBuilder
                                        .withPayload(event)
                                        .setHeader("credentialId", credentialOffer.getId())
                                        .setHeader("oldStatus", oldStatus)
                                        .setHeader(CredentialStateMachineConfig.CREDENTIAL_OFFER_HEADER, credentialOffer)
                                        .build()
                        )
                )
                .blockLast();

        assert stateMachineResult != null;
        if (stateMachineResult.getResultType().equals(StateMachineEventResult.ResultType.ACCEPTED)) {
            var newStatus = credentialOfferStateMachine.getState().getId();
            credentialOffer.setCredentialOfferStatus(newStatus);
            boolean stateChanged = oldStatus != newStatus;
            log.info("Transaction accepted for: {}. New state = {} (changed: {})",
                    stateMachineResult.getMessage(), newStatus, stateChanged);
            return new StateTransitionResult<>(newStatus, stateChanged);
        } else {
            log.error("Transaction failed for: {}.", stateMachineResult.getMessage());
            throw new IllegalStateException("Transition failed for " + stateMachineResult.getMessage());
        }
    }

    /**
     * Result of a state transition containing the new status and whether it changed.
     */
    public record StateTransitionResult<T>(T newStatus, boolean changed) {
    }
}
