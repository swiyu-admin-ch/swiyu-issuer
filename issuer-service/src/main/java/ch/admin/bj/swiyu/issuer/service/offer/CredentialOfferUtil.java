package ch.admin.bj.swiyu.issuer.service.offer;

import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStateMachine;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.statemachine.CredentialStateMachineConfig;
import lombok.experimental.UtilityClass;

@UtilityClass
public class CredentialOfferUtil {
    
    /**
     * Checks if a {@link CredentialOffer} has passed its expiration timestamp and is not already terminated.
     * If the offer has expired, it triggers the {@code EXPIRE} event on the provided {@link CredentialStateMachine}
     * and persists the updated offer via the {@link CredentialOfferRepository}.
     *
     * @param offer                     the credential offer to validate
     * @param credentialStateMachine    the state machine used to process state transitions
     * @param credentialOfferRepository the repository used to persist the updated offer
     * @return the offer if it is still valid; otherwise the saved, expired offer
     */
    public static CredentialOffer getExpirationCheckedCredentialOffer(CredentialOffer offer, CredentialStateMachine credentialStateMachine, CredentialOfferRepository credentialOfferRepository) {
        if (!offer.isTerminatedOffer()
                            && offer.hasExpirationTimeStampPassed()) {
                        credentialStateMachine.sendEventAndUpdateStatus(offer,
                                CredentialStateMachineConfig.CredentialOfferEvent.EXPIRE);
                        return credentialOfferRepository.save(offer);
                    }
        return offer;
    }
}
