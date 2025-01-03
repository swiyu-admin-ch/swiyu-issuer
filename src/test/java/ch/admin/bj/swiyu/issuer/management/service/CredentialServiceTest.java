package ch.admin.bj.swiyu.issuer.management.service;

import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.CredentialOfferEntity;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.CredentialOfferRepository;
import ch.admin.bj.swiyu.issuer.management.enums.CredentialStatusEnum;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest()
@ActiveProfiles("test")
@AutoConfigureMockMvc
public class CredentialServiceTest {
    @Autowired
    CredentialOfferRepository credentialOfferRepository;
    @Autowired
    CredentialService credentialService;


    @Test
    void invalidateExpiredOffer() {
        var repoCount = credentialOfferRepository.count();
        Map<String, Object> offerData = Map.of("hello", "world");
        var expiredId = credentialOfferRepository.save(CredentialOfferEntity.builder()
                .credentialStatus(CredentialStatusEnum.OFFERED)
                .offerExpirationTimestamp(Instant.now().getEpochSecond() - 1)
                .accessToken(UUID.randomUUID())
                .holderBindingNonce(UUID.randomUUID())
                .offerData(offerData)
                .build()).getId();
        var validId = credentialOfferRepository.save(
                CredentialOfferEntity.builder()
                        .credentialStatus(CredentialStatusEnum.OFFERED)
                        .offerExpirationTimestamp(Instant.now().getEpochSecond() + 1000)
                        .accessToken(UUID.randomUUID())
                        .holderBindingNonce(UUID.randomUUID())
                        .offerData(offerData)
                        .build()).getId();
        var issuedId = credentialOfferRepository.save(
                CredentialOfferEntity.builder()
                        .credentialStatus(CredentialStatusEnum.ISSUED)
                        .offerExpirationTimestamp(Instant.now().getEpochSecond() - 1)
                        .accessToken(UUID.randomUUID())
                        .holderBindingNonce(UUID.randomUUID())
                        // Note: Issued entries should have their data deleted by the VC signer component
                        .build()).getId();
        credentialOfferRepository.flush();

        var expiredOffer = credentialOfferRepository.findById(expiredId);
        var validOffer = credentialOfferRepository.findById(validId);
        var issuedOffer = credentialOfferRepository.findById(issuedId);
        assertThat(expiredOffer).isPresent();
        assertThat(validOffer).isPresent();
        assertThat(issuedOffer).isPresent();
        assertThat(expiredOffer.get().getCredentialStatus()).isEqualTo(CredentialStatusEnum.OFFERED);
        assertThat(validOffer.get().getCredentialStatus()).isEqualTo(CredentialStatusEnum.OFFERED);
        assertThat(issuedOffer.get().getCredentialStatus()).isEqualTo(CredentialStatusEnum.ISSUED);
        assertThat(expiredOffer.get().getOfferData()).isNotNull().isNotEmpty();
        assertThat(validOffer.get().getOfferData()).isNotNull().isNotEmpty();
        assertThat(issuedOffer.get().getOfferData()).isNull();
        credentialService.expireOffers();
        expiredOffer = credentialOfferRepository.findById(expiredId);
        validOffer = credentialOfferRepository.findById(validId);
        issuedOffer = credentialOfferRepository.findById(issuedId);
        assertThat(expiredOffer).isPresent();
        assertThat(validOffer).isPresent();
        assertThat(issuedOffer).isPresent();
        assertThat(expiredOffer.get().getCredentialStatus()).as("Expired offer should have a changed state").isEqualTo(CredentialStatusEnum.EXPIRED);
        assertThat(validOffer.get().getCredentialStatus()).as("Valid Offer should not have been changed").isEqualTo(CredentialStatusEnum.OFFERED);
        assertThat(issuedOffer.get().getCredentialStatus()).as("The state of issued VCs should not have been changed, despite the offer being expired").isEqualTo(CredentialStatusEnum.ISSUED);
        assertThat(expiredOffer.get().getOfferData()).as("Data of expired offers should be deleted").isNull();
        assertThat(validOffer.get().getOfferData()).as("Data of valid offers should have not been changed").isNotNull().isNotEmpty();
        assertThat(issuedOffer.get().getOfferData()).isNull();
    }
}
