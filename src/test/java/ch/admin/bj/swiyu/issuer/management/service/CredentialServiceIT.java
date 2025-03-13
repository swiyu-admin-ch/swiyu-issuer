/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.service;

import java.util.Map;
import java.util.UUID;

import static java.time.Instant.now;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.CredentialOfferRepository;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.CredentialStatusType;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest()
@ActiveProfiles("test")
@AutoConfigureMockMvc
public class CredentialServiceIT {
    @Autowired
    CredentialOfferRepository credentialOfferRepository;
    @Autowired
    CredentialService credentialService;

    @Test
    void offerDeeplinkTest() {
        // GIVEN
        Map<String, Object> offerData = Map.of("hello", "world");
        var validId = credentialOfferRepository.saveAndFlush(
                CredentialOffer.builder()
                        .credentialStatus(CredentialStatusType.OFFERED)
                        .offerExpirationTimestamp(now().plusSeconds(1000).getEpochSecond())
                        .accessToken(UUID.randomUUID())
                        .nonce(UUID.randomUUID())
                        .offerData(offerData)
                        .build()).getId();

        var validOffer = credentialOfferRepository.findById(validId);
        assertThat(validOffer.isPresent()).isTrue();
        // WHEN
        var validDeeplink = credentialService.getCredentialOfferDeeplink(validOffer.get().getId());
        // THEN
        assertThat(validDeeplink).isNotNull();
        System.out.println(validDeeplink);
        assertThat(validDeeplink.contains("version")).isTrue();

    }

    @Test
    void getCredentialInvalidateOfferWhenExpired() {
        // GIVEN
        Map<String, Object> offerData = Map.of("hello", "world");
        var expiredOfferdId = credentialOfferRepository.save(
                CredentialOffer.builder()
                        .credentialStatus(CredentialStatusType.OFFERED)
                        .offerExpirationTimestamp(now().minusSeconds(1).getEpochSecond())
                        .accessToken(UUID.randomUUID())
                        .nonce(UUID.randomUUID())
                        .offerData(offerData)
                        .build()).getId();
        // WHEN
        // note: getting an expired offer will imeediately update it to expired
        credentialService.getCredentialOffer(expiredOfferdId);
        // THEN
        var response = credentialOfferRepository.findById(expiredOfferdId).orElseThrow();
        assertEquals(CredentialStatusType.EXPIRED, response.getCredentialStatus());
        assertNull(response.getOfferData());
    }

    @Test
    void getDeeplinkInvalidateOfferWhenExpired() {
        // GIVEN
        Map<String, Object> offerData = Map.of("hello", "world");
        var expiredOfferdId = credentialOfferRepository.save(
                CredentialOffer.builder()
                        .credentialStatus(CredentialStatusType.OFFERED)
                        .offerExpirationTimestamp(now().minusSeconds(1).getEpochSecond())
                        .accessToken(UUID.randomUUID())
                        .nonce(UUID.randomUUID())
                        .offerData(offerData)
                        .build()).getId();

        // WHEN
        // note: getting an expired offer will immediately update it to expired
        credentialService.getCredentialOffer(expiredOfferdId);
        // THEN
        var credential = credentialOfferRepository.findById(expiredOfferdId).orElseThrow();
        assertEquals(CredentialStatusType.EXPIRED, credential.getCredentialStatus());
        assertNull(credential.getOfferData());
        var deepLink = credentialService.getCredentialOfferDeeplink(credential.getId());
        assertNotNull(deepLink);
        assertTrue(deepLink.startsWith("swiyu://"));
    }

    @Test
    void getCredentialOfferWhenNotExpired() {
        Map<String, Object> offerData = Map.of("hello", "world");
        var expiredOfferdId = credentialOfferRepository.save(
                CredentialOffer.builder()
                        .credentialStatus(CredentialStatusType.OFFERED)
                        .offerExpirationTimestamp(now().plusSeconds(20).getEpochSecond())
                        .accessToken(UUID.randomUUID())
                        .nonce(UUID.randomUUID())
                        .offerData(offerData)
                        .build()).getId();

        var response = credentialOfferRepository.findById(expiredOfferdId).orElseThrow();
        assertEquals(CredentialStatusType.OFFERED, response.getCredentialStatus());
        assertNotNull(response.getOfferData());
    }

    @Test
    void getCredentialOfferWhenExpiredAndRevoked() {
        Map<String, Object> offerData = Map.of("hello", "world");
        var expiredOfferdId = credentialOfferRepository.save(
                CredentialOffer.builder()
                        .credentialStatus(CredentialStatusType.REVOKED)
                        .offerExpirationTimestamp(now().minusSeconds(3600).getEpochSecond())
                        .accessToken(UUID.randomUUID())
                        .nonce(UUID.randomUUID())
                        .offerData(offerData)
                        .build()).getId();

        var response = credentialOfferRepository.findById(expiredOfferdId).orElseThrow();
        assertEquals(CredentialStatusType.REVOKED, response.getCredentialStatus());
        assertNotNull(response.getOfferData());
    }

    @Test
    void invalidateExpiredOffer() {
        Map<String, Object> offerData = Map.of("hello", "world");
        var expiredOfferdId = credentialOfferRepository.save(
                CredentialOffer.builder()
                        .credentialStatus(CredentialStatusType.OFFERED)
                        .offerExpirationTimestamp(now().minusSeconds(1).getEpochSecond())
                        .accessToken(UUID.randomUUID())
                        .nonce(UUID.randomUUID())
                        .offerData(offerData)
                        .build()).getId();

        var expiredInProgressId = credentialOfferRepository.save(
                CredentialOffer.builder()
                        .credentialStatus(CredentialStatusType.IN_PROGRESS)
                        .offerExpirationTimestamp(now().minusSeconds(1).getEpochSecond())
                        .accessToken(UUID.randomUUID())
                        .nonce(UUID.randomUUID())
                        .offerData(offerData)
                        .build()).getId();

        var validId = credentialOfferRepository.save(
                CredentialOffer.builder()
                        .credentialStatus(CredentialStatusType.OFFERED)
                        .offerExpirationTimestamp(now().plusSeconds(1000).getEpochSecond())
                        .accessToken(UUID.randomUUID())
                        .nonce(UUID.randomUUID())
                        .offerData(offerData)
                        .build()).getId();

        var issuedId = credentialOfferRepository.save(
                CredentialOffer.builder()
                        .credentialStatus(CredentialStatusType.ISSUED)
                        .offerExpirationTimestamp(now().minusSeconds(1).getEpochSecond())
                        .accessToken(UUID.randomUUID())
                        .nonce(UUID.randomUUID())
                        // Note: Issued entries should have their data deleted by the VC signer component
                        .build()).getId();
        credentialOfferRepository.flush();

        var expiredOffered = credentialOfferRepository.findById(expiredOfferdId);
        var expiredInProgress = credentialOfferRepository.findById(expiredInProgressId);
        var validOffer = credentialOfferRepository.findById(validId);
        var issuedOffer = credentialOfferRepository.findById(issuedId);

        assertThat(expiredOffered).isPresent();
        assertThat(expiredInProgress).isPresent();
        assertThat(validOffer).isPresent();
        assertThat(issuedOffer).isPresent();

        assertThat(expiredOffered.get().getCredentialStatus()).isEqualTo(CredentialStatusType.OFFERED);
        assertThat(expiredInProgress.get().getCredentialStatus()).isEqualTo(CredentialStatusType.IN_PROGRESS);
        assertThat(validOffer.get().getCredentialStatus()).isEqualTo(CredentialStatusType.OFFERED);
        assertThat(issuedOffer.get().getCredentialStatus()).isEqualTo(CredentialStatusType.ISSUED);

        assertThat(expiredOffered.get().getOfferData()).isNotNull().isNotEmpty();
        assertThat(expiredInProgress.get().getOfferData()).isNotNull().isNotEmpty();
        assertThat(validOffer.get().getOfferData()).isNotNull().isNotEmpty();
        assertThat(issuedOffer.get().getOfferData()).isNull();

        credentialService.expireOffers();

        expiredOffered = credentialOfferRepository.findById(expiredOfferdId);
        expiredInProgress = credentialOfferRepository.findById(expiredOfferdId);
        validOffer = credentialOfferRepository.findById(validId);
        issuedOffer = credentialOfferRepository.findById(issuedId);

        assertThat(expiredOffered).isPresent();
        assertThat(expiredInProgress).isPresent();
        assertThat(validOffer).isPresent();
        assertThat(issuedOffer).isPresent();

        assertThat(expiredOffered.get().getCredentialStatus()).as("Expired offer should have a changed state").isEqualTo(CredentialStatusType.EXPIRED);
        assertThat(expiredInProgress.get().getCredentialStatus()).as("Expired offer should have a changed state").isEqualTo(CredentialStatusType.EXPIRED);
        assertThat(validOffer.get().getCredentialStatus()).as("Valid Offer should not have been changed").isEqualTo(CredentialStatusType.OFFERED);
        assertThat(issuedOffer.get().getCredentialStatus()).as("The state of issued VCs should not have been changed, despite the offer being expired").isEqualTo(CredentialStatusType.ISSUED);

        assertThat(expiredOffered.get().getOfferData()).as("Data of expired offers should be deleted").isNull();
        assertThat(expiredInProgress.get().getOfferData()).as("Data of expired offers should be deleted").isNull();
        assertThat(validOffer.get().getOfferData()).as("Data of valid offers should have not been changed").isNotNull().isNotEmpty();
        assertThat(issuedOffer.get().getOfferData()).isNull();
    }
}
