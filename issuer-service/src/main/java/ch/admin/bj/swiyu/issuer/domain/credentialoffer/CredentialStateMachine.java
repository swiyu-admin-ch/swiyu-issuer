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

    // Kapselt die StateMachine-Logik für CredentialManagement
    public void sendEventAndUpdateStatus(CredentialManagement entity, CredentialStateMachineConfig.CredentialManagementEvent event) {

        credentialManagementStateMachine.getStateMachineAccessor()
                .doWithAllRegions(access ->
                        access.resetStateMachineReactively(
                                new DefaultStateMachineContext<>(
                                        entity.getCredentialManagementStatus(),
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
                                        .setHeader("oldStatus", entity.getCredentialManagementStatus())
                                        .build()
                        )
                )
                .blockLast();

        assert success != null;
        if (success.getResultType().equals(StateMachineEventResult.ResultType.ACCEPTED)) {
            entity.setCredentialManagementStatus(credentialManagementStateMachine.getState().getId());
            log.info("Transaction accepted for: {}. New state = {}", success.getMessage(), entity.getCredentialManagementStatus());
        } else {
            log.error("Transaction failed for: {}.", success.getMessage());
            throw new IllegalStateException("Transition failed for " + success.getMessage());
        }
    }

    public void sendEventAndUpdateStatus(CredentialOffer entity, CredentialStateMachineConfig.CredentialOfferEvent event) {

        credentialOfferStateMachine.getStateMachineAccessor()
                .doWithAllRegions(access ->
                        access.resetStateMachineReactively(
                                new DefaultStateMachineContext<>(
                                        entity.getCredentialStatus(),
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
                                        .setHeader("oldStatus", entity.getCredentialStatus())
                                        .setHeader(CredentialStateMachineConfig.CREDENTIAL_OFFER_HEADER, entity)
                                        .build()
                        )
                )
                .blockLast();

        assert success != null;
        if (success.getResultType().equals(StateMachineEventResult.ResultType.ACCEPTED)) {
            entity.changeStatus(credentialOfferStateMachine.getState().getId());
            log.info("Transaction accepted for: {}. New state = {}", success.getMessage(), entity.getCredentialStatus());
        } else {
            log.error("Transaction failed for: {}.", success.getMessage());
            throw new IllegalStateException("Transition failed for " + success.getMessage());
        }
    }
}
