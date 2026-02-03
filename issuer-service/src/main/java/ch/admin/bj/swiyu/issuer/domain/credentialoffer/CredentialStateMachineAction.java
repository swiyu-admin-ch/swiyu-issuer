package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import ch.admin.bj.swiyu.issuer.service.webhook.EventProducerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.statemachine.action.Action;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class CredentialStateMachineAction {
    private final EventProducerService eventProducer;

    @Autowired
    public CredentialStateMachineAction(EventProducerService eventProducer) {
        this.eventProducer = eventProducer;
    }

    Action<CredentialStatusManagementType, CredentialStateMachineConfig.CredentialManagementEvent> managementStateChangeAction() {
        return ctx -> {
            var managementId = (UUID) ctx.getMessageHeader("credentialId");
            var target = ctx.getTarget().getId();
            eventProducer.produceManagementStateChangeEvent(managementId, target);
        };
    }

    Action<CredentialOfferStatusType, CredentialStateMachineConfig.CredentialOfferEvent> offerStateChange() {
        return ctx -> {
            var offerId = (UUID) ctx.getMessageHeader("credentialId");
            var target = ctx.getTarget().getId();
            eventProducer.produceOfferStateChangeEvent(offerId, target);
        };
    }

    public Action<CredentialOfferStatusType, CredentialStateMachineConfig.CredentialOfferEvent> invalidateOfferDataAction() {
        return context -> {
            var message = context.getMessage();
            if (message != null && message.getHeaders().containsKey(CredentialStateMachineConfig.CREDENTIAL_OFFER_HEADER)) {
                Object offerObj = message.getHeaders().get(CredentialStateMachineConfig.CREDENTIAL_OFFER_HEADER);
                if (offerObj instanceof CredentialOffer offer) {
                    offer.invalidateOfferData();
                }
            }
        };
    }
}
