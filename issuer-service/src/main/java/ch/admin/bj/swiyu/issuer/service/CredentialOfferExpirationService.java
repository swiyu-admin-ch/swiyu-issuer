package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusType;
import ch.admin.bj.swiyu.issuer.service.persistence.CredentialPersistenceService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * Service responsible for expiring a single credential offer.
 *
 * <p>Each offer is expired in its own transaction. This isolates failures: an offer which can not be read or can not
 * be transitioned (e.g. because its persisted data is invalid or outdated) is rolled back on its own and does not
 * affect the expiration of any other offer.</p>
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class CredentialOfferExpirationService {

    private final CredentialPersistenceService persistenceService;
    private final CredentialStateService stateService;

    /**
     * Expires the offer by ID if it is in an expirable state and past its expiration timestamp.
     *
     * @param offerId the UUID of the offer
     * @return {@code true} if the offer was expired, {@code false} if it was skipped because it is no longer expired
     * @throws ch.admin.bj.swiyu.issuer.common.exception.ResourceNotFoundException if no offer with the given ID exists
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public boolean expireOffer(UUID offerId) {
        var offer = persistenceService.findCredentialOfferByIdForUpdate(offerId);

        if (!isExpired(offer)) {
            log.debug("Skipping credential offer {} in status {} with expiration timestamp {}: no longer expired",
                    offerId, offer.getCredentialStatus(), offer.getOfferExpirationTimestamp());
            return false;
        }

        stateService.expireOfferAndPublish(offer);
        return true;
    }

    /**
     * Expires an offer by updating its state and publishing an event.
     *
     * @param offer the offer to expire
     * @throws BadRequestException if the offer is already in a terminal state
     * @return either expired {@link CredentialOffer} or returns it untouched
     */
    @Transactional(propagation = Propagation.REQUIRED)
    public CredentialOffer expireCredentialOffer(CredentialOffer offer) {
        var currentStatus = offer.getCredentialStatus();

        // throw error on forbidden operation
        if (currentStatus.isTerminalState()) {
            throw new BadRequestException(
                    String.format("Tried to set %s but status is already %s", CredentialOfferStatusType.EXPIRED, currentStatus));
        }

        if (isExpired(offer)) {
            return stateService.expireOfferAndPublish(offer);
        }

        return offer;
    }

    // expire if offer is in an expirable state and timestamp is in past
    private boolean isExpired(CredentialOffer offer) {
        return CredentialOfferStatusType.getExpirableStates().contains(offer.getCredentialStatus())
                && offer.hasExpirationTimeStampPassed();
    }
}
