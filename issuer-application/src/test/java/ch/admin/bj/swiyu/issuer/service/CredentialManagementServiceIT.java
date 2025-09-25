package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.util.*;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest()
@Nested
@DisplayName("Credential Management Service")
@AutoConfigureMockMvc
@Testcontainers
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
class CredentialManagementServiceIT {

    @Autowired
    CredentialManagementService credentialManagementService;
    @Autowired
    CredentialOfferRepository credentialOfferRepository;

    @Test
    void testExpireOffersAllCredentialStatusType() {
        final List<CredentialStatusType> expirableStatus = List.of(
                CredentialStatusType.OFFERED,
                CredentialStatusType.IN_PROGRESS,
                CredentialStatusType.DEFERRED,
                CredentialStatusType.READY
        );
        final long past = Instant.now().minusSeconds(300).getEpochSecond();
        final long future = Instant.now().plusSeconds(300).getEpochSecond();

        final List<CredentialOffer> allOffers = Arrays.stream(CredentialStatusType.values())
                .flatMap(status -> Stream.of(newOffer(status, past), newOffer(status, future)))
                .map(credentialOfferRepository::save)
                .toList();

        final List<CredentialOffer> expectedExpired = allOffers.stream()
                .filter(o ->
                        (expirableStatus.contains(o.getCredentialStatus()) && o.getOfferExpirationTimestamp() < Instant.now().getEpochSecond())
                                || o.getCredentialStatus() == CredentialStatusType.EXPIRED
                )
                .toList();

        final List<CredentialOffer> expectedUnchanged = new ArrayList<>(allOffers);
        expectedUnchanged.removeAll(expectedExpired);

        credentialManagementService.expireOffers();

        for (var offer : expectedExpired) {
            final CredentialOffer offerUpdated = credentialOfferRepository.findById(offer.getId()).orElseThrow();
            assertThat(offerUpdated.getCredentialStatus()).isEqualTo(CredentialStatusType.EXPIRED);
        }

        for (var offer : expectedUnchanged) {
            final CredentialOffer offerUpdated = credentialOfferRepository.findById(offer.getId()).orElseThrow();
            assertThat(offerUpdated.getCredentialStatus()).isEqualTo(offer.getCredentialStatus());
        }
    }

    private static CredentialOffer newOffer(final CredentialStatusType status, final long expirationEpoch) {
        return CredentialOffer.builder()
                .credentialStatus(status)
                .metadataCredentialSupportedId(List.of("metadata"))
                .offerData(Map.of())
                .offerExpirationTimestamp(expirationEpoch)
                .nonce(UUID.randomUUID())
                .accessToken(UUID.randomUUID())
                .preAuthorizedCode(UUID.randomUUID())
                .build();
    }
}
