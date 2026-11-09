package ch.admin.bj.swiyu.issuer.infrastructure.scheduler;

import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusType;
import ch.admin.bj.swiyu.issuer.service.CredentialOfferExpirationService;
import ch.admin.bj.swiyu.issuer.service.persistence.CredentialPersistenceService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Scheduled job that expires credential offers whose expiration timestamp has passed.
 *
 * <p>Finds offers in expirable states with an offer expiration timestamp less than the
 * current time, updates their status to {@link CredentialOfferStatusType#EXPIRED} and triggers
 * the usual status-change processing (including deletion of associated person data).
 * Runs according to the configured {@code application.offer-expiration-interval} and uses
 * a distributed lock ("expireOffers") to avoid concurrent execution across instances.</p>
 *
 * <p>The job is resilient per offer: every offer is expired in its own transaction, and a single
 * offer which can not be processed (e.g. because its persisted data can no longer be read) is
 * logged and skipped instead of aborting the expiration of all remaining offers.</p>
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class CredentialOfferExpirationScheduler {

    private final CredentialPersistenceService persistenceService;
    private final CredentialOfferExpirationService credentialOfferExpirationService;

    @Scheduled(initialDelay = 0, fixedDelayString = "${application.offer-expiration-interval}")
    @SchedulerLock(name = "expireOffers")
    public void expireOffers() {
        var expireStates = CredentialOfferStatusType.getExpirableStates();
        var expireTimeStamp = Instant.now().getEpochSecond();

        List<UUID> expiringOfferIds = persistenceService.findExpiredOfferIds(expireStates, expireTimeStamp);
        log.info("Expiring {} offers", expiringOfferIds.size());

        List<UUID> failedOfferIds = new ArrayList<>();
        for (var offerId : expiringOfferIds) {
            try {
                credentialOfferExpirationService.expireOffer(offerId);
            } catch (RuntimeException e) {
                // A broken offer should not prevent the remaining offers from being expired.
                failedOfferIds.add(offerId);
                log.error("Could not expire offer {} - Please check the entry manually", offerId, e);
            }
        }

        if (!failedOfferIds.isEmpty()) {
            log.warn("{} of {} credential offers could not be expired: {}", failedOfferIds.size(), expiringOfferIds.size(), failedOfferIds);
        }
    }
}
