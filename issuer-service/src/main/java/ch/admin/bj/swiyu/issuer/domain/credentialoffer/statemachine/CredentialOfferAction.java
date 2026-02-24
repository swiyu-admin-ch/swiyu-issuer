package ch.admin.bj.swiyu.issuer.domain.credentialoffer.statemachine;

import org.springframework.messaging.Message;
import org.springframework.statemachine.action.Action;
import org.springframework.stereotype.Component;

import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusType;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.statemachine.CredentialStateMachineConfig.CredentialOfferEvent;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class CredentialOfferAction {
    public Action<CredentialOfferStatusType, CredentialStateMachineConfig.CredentialOfferEvent> invalidateOfferDataAction() {
        return context -> {
            var message = context.getMessage();
            CredentialOffer offer = extractCredentialOffer(message);
            offer.invalidateOfferData();
            if (context.getTarget().getId() == CredentialOfferStatusType.ISSUED) {
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
        throw new IllegalStateException("Received no or the wrong object in CREDENTIAL_OFFER_HEADER");
    }
}
