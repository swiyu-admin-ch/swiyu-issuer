package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStateMachineConfig.CredentialOfferEvent;
import ch.admin.bj.swiyu.issuer.service.webhook.EventProducerService;
import lombok.RequiredArgsConstructor;

import org.springframework.messaging.Message;
import org.springframework.statemachine.action.Action;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
@RequiredArgsConstructor
public class CredentialStateMachineAction {
    private final EventProducerService eventProducer;

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
            CredentialOffer offer = extractCredentialOffer(message);
            offer.invalidateOfferData();
            if(context.getTarget().getId() == CredentialOfferStatusType.ISSUED) {
                // Also delete Transaction ID if the new state is issued. 
                offer.setTransactionId(null);
            }
        };
    }

    private CredentialOffer extractCredentialOffer(Message<CredentialOfferEvent> message) {
        if (message != null && message.getHeaders().containsKey(CredentialStateMachineConfig.CREDENTIAL_OFFER_HEADER)) {
                Object offerObj = message.getHeaders().get(CredentialStateMachineConfig.CREDENTIAL_OFFER_HEADER);
            if (offerObj instanceof CredentialOffer offer) {
                return offer;
            }
        }
        throw new IllegalStateException("Received the wrong object in CREDENTIAL_OFFER_HEADER");
    }
}
