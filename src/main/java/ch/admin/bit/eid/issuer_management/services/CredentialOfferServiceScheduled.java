package ch.admin.bit.eid.issuer_management.services;

import ch.admin.bit.eid.issuer_management.domain.CredentialOfferRepository;
import ch.admin.bit.eid.issuer_management.enums.CredentialStatusEnum;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.EnableSchedulerLock;
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Slf4j
@Service
@RequiredArgsConstructor
@EnableScheduling
@EnableSchedulerLock(defaultLockAtMostFor = "5m")
public class CredentialOfferServiceScheduled {

    private final CredentialOfferRepository credentialOfferRepository;

    @Scheduled(initialDelay = 0, fixedDelayString = "${application.offer-expiration-interval}")
    @SchedulerLock(name = "expireOffers")
    @Transactional
    public void expireOffers() {
        var expiredOffers = credentialOfferRepository.findByOfferExpirationTimestampLessThan(Instant.now().getEpochSecond());
        expiredOffers.forEach(offer -> {
            offer.changeStatus(CredentialStatusEnum.EXPIRED);
            offer.removeOfferData();
        });
    }
}
