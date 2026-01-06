package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.statemachine.StateMachineEventResult;
import org.springframework.statemachine.support.DefaultStateMachineContext;
import org.springframework.stereotype.Service;
import org.springframework.statemachine.StateMachine;
import reactor.core.publisher.Mono;

@Service
@Slf4j
public class CredentialStateMachine {
    private final StateMachine<CredentialStatusManagementType, CredentialStateMachineConfig.CredentialManagementEvent> credentialManagementStateMachine;
    private final StateMachine<CredentialOfferStatusType, CredentialStateMachineConfig.CredentialOfferEvent> credentialOfferStateMachine;

    @Autowired
    public CredentialStateMachine(
        StateMachine<CredentialStatusManagementType, CredentialStateMachineConfig.CredentialManagementEvent> credentialManagementStateMachine,
        StateMachine<CredentialOfferStatusType, CredentialStateMachineConfig.CredentialOfferEvent> credentialOfferStateMachine
    ) {
        this.credentialManagementStateMachine = credentialManagementStateMachine;
        this.credentialOfferStateMachine = credentialOfferStateMachine;
    }

    /**
     * Send event to CredentialManagement state machine and update status.
     *
     * @param entity The CredentialManagement entity
     * @param event The event to send
     * @return The result containing the new status and whether the state changed
     */
    public StateTransitionResult<CredentialStatusManagementType> sendEventAndUpdateStatus(
            CredentialManagement entity,
            CredentialStateMachineConfig.CredentialManagementEvent event) {

        if (event == null){
            log.info("No transaction requested for {} in state {}", entity.getId(), entity.getCredentialManagementStatus());
            return new StateTransitionResult<>(entity.getCredentialManagementStatus(), false);
        }

        var oldStatus = entity.getCredentialManagementStatus();

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

        StateMachineEventResult<CredentialStatusManagementType, CredentialStateMachineConfig.CredentialManagementEvent> success = credentialManagementStateMachine
                .sendEvent(
                        Mono.just(
                                MessageBuilder
                                        .withPayload(event)
                                        .setHeader("credentialId", entity.getId())
                                        .setHeader("oldStatus", oldStatus)
                                        .setHeader(CredentialStateMachineConfig.CREDENTIAL_MANAGEMENT_HEADER, entity)
                                        .build()
                        )
                )
                .blockLast();

        assert success != null;
        if (success.getResultType().equals(StateMachineEventResult.ResultType.ACCEPTED)) {
            var newStatus = credentialManagementStateMachine.getState().getId();
            entity.setCredentialManagementStatus(newStatus);
            boolean stateChanged = oldStatus != newStatus;
            log.info("Transaction accepted for: {}. New state = {} (changed: {})",
                    success.getMessage(), newStatus, stateChanged);
            return new StateTransitionResult<>(newStatus, stateChanged);
        } else {
            log.error("Transaction failed for: {}.", success.getMessage());
            throw new IllegalStateException("Transition failed for " + success.getMessage());
        }
    }

    /**
     * Send event to CredentialOffer state machine and update status.
     *
     * @param entity The CredentialOffer entity
     * @param event The event to send
     * @return The result containing the new status and whether the state changed
     */
    public StateTransitionResult<CredentialOfferStatusType> sendEventAndUpdateStatus(
            CredentialOffer entity,
            CredentialStateMachineConfig.CredentialOfferEvent event) {

        if (event == null){
            log.info("No transaction requested for {} in state {}", entity.getId(), entity.getCredentialStatus());
            return new StateTransitionResult<>(entity.getCredentialStatus(), false);
        }

        var oldStatus = entity.getCredentialStatus();

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

        StateMachineEventResult<CredentialOfferStatusType, CredentialStateMachineConfig.CredentialOfferEvent> success = credentialOfferStateMachine
                .sendEvent(
                        Mono.just(
                                MessageBuilder
                                        .withPayload(event)
                                        .setHeader("credentialId", entity.getId())
                                        .setHeader("oldStatus", oldStatus)
                                        .setHeader(CredentialStateMachineConfig.CREDENTIAL_OFFER_HEADER, entity)
                                        .build()
                        )
                )
                .blockLast();

        assert success != null;
        if (success.getResultType().equals(StateMachineEventResult.ResultType.ACCEPTED)) {
            var newStatus = credentialOfferStateMachine.getState().getId();
            entity.setCredentialOfferStatusJustForTestUsage(newStatus);
            boolean stateChanged = oldStatus != newStatus;
            log.info("Transaction accepted for: {}. New state = {} (changed: {})",
                    success.getMessage(), newStatus, stateChanged);
            return new StateTransitionResult<>(newStatus, stateChanged);
        } else {
            log.error("Transaction failed for: {}.", success.getMessage());
            throw new IllegalStateException("Transition failed for " + success.getMessage());
        }
    }

    /**
     * Result of a state transition containing the new status and whether it changed.
     */
    public record StateTransitionResult<T>(T newStatus, boolean changed) {}
}
