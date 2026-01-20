package ch.admin.bj.swiyu.issuer.service.credential;

import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * Handles credential-offer-related state transitions and expiration checks.
 */
@Slf4j
@Service
@AllArgsConstructor
public class CredentialOfferStateService {

    private final CredentialStateMachine credentialStateMachine;
    private final CredentialOfferRepository credentialOfferRepository;

    /**
     * Returns the first offer that is currently in progress.
     */
    public Optional<CredentialOffer> getFirstOffersInProgress(CredentialManagement mgmt) {
        return mgmt.getCredentialOffers().stream()
                .filter(offer -> offer.getCredentialStatus() == CredentialOfferStatusType.IN_PROGRESS)
                .findFirst();
    }

    /**
     * Marks expired offers as terminated.
     */
    public void checkIfAnyOfferExpiredAndUpdate(CredentialManagement mgmt) {
        mgmt.getCredentialOffers().forEach(this::terminateExpiredOffer);
    }

    private void terminateExpiredOffer(CredentialOffer offer) {
        if (!offer.isTerminatedOffer() && offer.hasExpirationTimeStampPassed()) {
            credentialStateMachine.sendEventAndUpdateStatus(
                    offer, CredentialStateMachineConfig.CredentialOfferEvent.EXPIRE);
            credentialOfferRepository.save(offer);
        }
    }
}

