package ch.admin.bj.swiyu.issuer.infrastructure.scheduler;

import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusType;
import ch.admin.bj.swiyu.issuer.service.persistence.CredentialPersistenceService;
import ch.admin.bj.swiyu.issuer.service.CredentialStateService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/**
 * Scheduled job that expires credential offers whose expiration timestamp has passed.
 *
 * <p>Finds offers in expirable states with an offer expiration timestamp less than the
 * current time, updates their status to {@link CredentialOfferStatusType#EXPIRED} and triggers
 * the usual status-change processing (including deletion of associated person data).
 * Runs according to the configured {@code application.offer-expiration-interval} and uses
 * a distributed lock ("expireOffers") to avoid concurrent execution across instances.
 * Executes within a transaction.</p>
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class CredentialOfferExpirationScheduler {

    private final CredentialPersistenceService persistenceService;
    private final CredentialStateService stateService;

    @Scheduled(initialDelay = 0, fixedDelayString = "${application.offer-expiration-interval}")
    @SchedulerLock(name = "expireOffers")
    @Transactional
    public void expireOffers() {
        var expireStates = CredentialOfferStatusType.getExpirableStates();
        var expireTimeStamp = Instant.now().getEpochSecond();

        log.info("Expiring {} offers", persistenceService.countExpiredOffers(expireStates, expireTimeStamp));

        var expiredOffers = persistenceService.findExpiredOffers(expireStates, expireTimeStamp);
        expiredOffers.forEach(offer -> {
            stateService.expireOfferAndPublish(offer);
            persistenceService.saveCredentialOffer(offer);
        });
    }


}

