package ch.admin.bj.swiyu.issuer.domain.credentialoffer.statemachine;

import java.util.Set;

import org.springframework.messaging.Message;
import org.springframework.statemachine.StateContext;
import org.springframework.statemachine.action.Action;
import org.springframework.stereotype.Component;

import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialManagement;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatus;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusManagementType;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.statemachine.CredentialStateMachineConfig.CredentialManagementEvent;
import ch.admin.bj.swiyu.issuer.service.persistence.CredentialPersistenceService;
import ch.admin.bj.swiyu.issuer.service.statuslist.StatusListPersistenceService;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class CredentialManagementAction {
        private final CredentialPersistenceService persistenceService;
        private final StatusListPersistenceService statusListPersistenceService;

        public Action<CredentialStatusManagementType, CredentialManagementEvent> revokeAction() {
            return ctx -> {
                var offerStatusSet = prepareOfferStatusSet(ctx);
                statusListPersistenceService.revoke(offerStatusSet);
            };
        }
        public Action<CredentialStatusManagementType, CredentialManagementEvent> suspendAction() {
            return ctx -> {
                var offerStatusSet = prepareOfferStatusSet(ctx);
                statusListPersistenceService.suspend(offerStatusSet);
            };
        }
        public Action<CredentialStatusManagementType, CredentialManagementEvent> revalidateAction() {
            return ctx -> {
                var offerStatusSet = prepareOfferStatusSet(ctx);
                statusListPersistenceService.revalidate(offerStatusSet);
            };
        }


        private Set<CredentialOfferStatus> prepareOfferStatusSet(
                StateContext<CredentialStatusManagementType, CredentialManagementEvent> ctx) {
            var management = extractCredentialManagement(ctx.getMessage());
            // Handle status list updates for post-issuance
            var affectedOffers = management.getCredentialOffers().stream()
                    .map(CredentialOffer::getId)
                    .toList();

            var offerStatusSet = persistenceService.findCredentialOfferStatusesByOfferIds(affectedOffers);
            return offerStatusSet;
        }


    private CredentialManagement extractCredentialManagement(Message<CredentialManagementEvent> message) {
        if (message != null && message.getHeaders().containsKey(CredentialStateMachineConfig.CREDENTIAL_MANAGEMENT_HEADER)) {
            Object offerObj = message.getHeaders().get(CredentialStateMachineConfig.CREDENTIAL_MANAGEMENT_HEADER);
            if (offerObj instanceof CredentialManagement management) {
                return management;
            }
        }
        throw new IllegalStateException("Received no or the wrong object in CREDENTIAL_MANAGEMENT_HEADER");
    }

}
