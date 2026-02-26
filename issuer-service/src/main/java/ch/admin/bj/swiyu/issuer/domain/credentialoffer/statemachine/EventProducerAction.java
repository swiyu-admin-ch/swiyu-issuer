package ch.admin.bj.swiyu.issuer.domain.credentialoffer.statemachine;

import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusType;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusManagementType;
import ch.admin.bj.swiyu.issuer.service.webhook.EventProducerService;
import lombok.RequiredArgsConstructor;

import org.springframework.statemachine.action.Action;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
@RequiredArgsConstructor
public class EventProducerAction {
    private static final String CREDENTIAL_ID = "credentialId";
    private final EventProducerService eventProducer;

    Action<CredentialStatusManagementType, CredentialStateMachineConfig.CredentialManagementEvent> managementStateChangeAction() {
        return ctx -> {
            var managementId = (UUID) ctx.getMessageHeader(CREDENTIAL_ID);
            var target = ctx.getTarget().getId();
            eventProducer.produceManagementStateChangeEvent(managementId, target);
        };
    }

    Action<CredentialOfferStatusType, CredentialStateMachineConfig.CredentialOfferEvent> offerStateChange() {
        return ctx -> {
            var offerId = (UUID) ctx.getMessageHeader(CREDENTIAL_ID);
            var target = ctx.getTarget().getId();
            eventProducer.produceOfferStateChangeEvent(offerId, target);
        };
    }
}
