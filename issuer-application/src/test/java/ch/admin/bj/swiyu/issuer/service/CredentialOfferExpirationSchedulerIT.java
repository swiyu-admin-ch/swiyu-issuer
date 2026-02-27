package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.infrastructure.scheduler.CredentialOfferExpirationScheduler;
import ch.admin.bj.swiyu.issuer.service.management.CredentialManagementService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.util.*;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest()
@DisplayName("Credential Management Service")
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
//@Transactional will break filtering to currently used indexes
class CredentialOfferExpirationSchedulerIT {
    @Autowired
    CredentialManagementService credentialManagementService;
    @Autowired
    CredentialOfferRepository credentialOfferRepository;
    @Autowired
    CredentialManagementRepository credentialManagementRepository;
    @Autowired
    CredentialOfferExpirationScheduler credentialOfferExpirationScheduler;


    @Test
    void testExpireOffersAllCredentialStatusType() {
        final List<CredentialOfferStatusType> expirableStatus = List.of(
                CredentialOfferStatusType.OFFERED,
                CredentialOfferStatusType.IN_PROGRESS,
                CredentialOfferStatusType.DEFERRED,
                CredentialOfferStatusType.REQUESTED,
                CredentialOfferStatusType.READY
        );
        final long past = Instant.now().minusSeconds(300).getEpochSecond();
        final long future = Instant.now().plusSeconds(300).getEpochSecond();

        final List<CredentialOffer> allOffers = Arrays.stream(CredentialOfferStatusType.values())
                .flatMap(status -> Stream.of(newOffer(status, past), newOffer(status, future)))
                .map(credentialOfferRepository::save)
                .toList();

        try {
            final List<CredentialOffer> expectedExpired = allOffers.stream()
                    .filter(o ->
                            (expirableStatus.contains(o.getCredentialStatus()) &&
                                    o.getOfferExpirationTimestamp() < Instant.now().getEpochSecond())
                                    || o.getCredentialStatus() == CredentialOfferStatusType.EXPIRED
                    )
                    .toList();

            final List<CredentialOffer> expectedUnchanged = new ArrayList<>(allOffers);
            expectedUnchanged.removeAll(expectedExpired);

            credentialOfferExpirationScheduler.expireOffers();

            for (var offer : expectedExpired) {
                final CredentialOffer offerUpdated = credentialOfferRepository.findById(offer.getId()).orElseThrow();
                assertThat(offerUpdated.getCredentialStatus()).isEqualTo(CredentialOfferStatusType.EXPIRED);
            }

            for (var offer : expectedUnchanged) {
                final CredentialOffer offerUpdated = credentialOfferRepository.findById(offer.getId()).orElseThrow();
                assertThat(offerUpdated.getCredentialStatus()).isEqualTo(offer.getCredentialStatus());
            }
        } finally {
            credentialOfferRepository.deleteAllById(
                    allOffers.stream().map(CredentialOffer::getId).toList()
            );
        }
    }

    private CredentialOffer newOffer(final CredentialOfferStatusType status, final long expirationEpoch) {
        var credentialManagement = credentialManagementRepository.save(CredentialManagement.builder()
                .id(UUID.randomUUID())
                .accessToken(UUID.randomUUID())
                .credentialManagementStatus(CredentialStatusManagementType.INIT)
                .accessTokenExpirationTimestamp(Instant.now().plusSeconds(120).getEpochSecond())
                .renewalRequestCnt(0)
                .renewalResponseCnt(0)
                .build());

        var offer = credentialOfferRepository.save(CredentialOffer.builder()
                .credentialStatus(status)
                .metadataCredentialSupportedId(List.of("metadata"))
                .offerData(Map.of())
                .offerExpirationTimestamp(expirationEpoch)
                .preAuthorizedCode(UUID.randomUUID())
                .credentialManagement(credentialManagement)
                .build());

        credentialManagement.addCredentialOffer(offer);
        credentialManagementRepository.save(credentialManagement);
        return offer;
    }
}