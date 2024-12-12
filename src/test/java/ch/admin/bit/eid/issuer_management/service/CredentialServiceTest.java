package ch.admin.bit.eid.issuer_management.service;

import ch.admin.bit.eid.issuer_management.domain.CredentialOfferRepository;
import ch.admin.bit.eid.issuer_management.domain.entities.CredentialOffer;
import ch.admin.bit.eid.issuer_management.enums.CredentialStatusEnum;
import ch.admin.bit.eid.issuer_management.services.CredentialOfferServiceScheduled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@SpringBootTest()
@ActiveProfiles("test")
@AutoConfigureMockMvc
public class CredentialServiceTest {
    @Autowired
    CredentialOfferRepository credentialOfferRepository;
    @Autowired
    CredentialOfferServiceScheduled credentialOfferServiceScheduled;


    @Test
    void invalidateExpiredOffer() {
        var repoCount = credentialOfferRepository.count();
        Map<String, Object> offerData = Map.of("hello", "world");
        var expiredId = credentialOfferRepository.save(CredentialOffer.builder()
                .credentialStatus(CredentialStatusEnum.OFFERED)
                .offerExpirationTimestamp(Instant.now().getEpochSecond() - 1)
                .accessToken(UUID.randomUUID())
                .holderBindingNonce(UUID.randomUUID())
                .offerData(offerData)
                .build()).getId();
        var validId = credentialOfferRepository.save(
                CredentialOffer.builder()
                        .credentialStatus(CredentialStatusEnum.OFFERED)
                        .offerExpirationTimestamp(Instant.now().getEpochSecond() + 1000)
                        .accessToken(UUID.randomUUID())
                        .holderBindingNonce(UUID.randomUUID())
                        .offerData(offerData)
                        .build()).getId();
        credentialOfferRepository.flush();
        assert credentialOfferRepository.count() == repoCount + 2;
        var expiredOffer = credentialOfferRepository.findById(expiredId);
        var validOffer = credentialOfferRepository.findById(validId);
        assert expiredOffer.isPresent();
        assert validOffer.isPresent();
        assert expiredOffer.get().getOfferData() != null && expiredOffer.get().getOfferData().size() == 1;
        assert validOffer.get().getOfferData() != null && validOffer.get().getOfferData().size() == 1;
        assert expiredOffer.get().getCredentialStatus() == CredentialStatusEnum.OFFERED;
        assert validOffer.get().getCredentialStatus() == CredentialStatusEnum.OFFERED;
        credentialOfferServiceScheduled.expireOffers();
        expiredOffer = credentialOfferRepository.findById(expiredId);
        validOffer = credentialOfferRepository.findById(validId);
        assert expiredOffer.isPresent();
        assert validOffer.isPresent();
        assert expiredOffer.get().getOfferData() == null;
        assert validOffer.get().getOfferData() != null && validOffer.get().getOfferData().size() == 1;
        assert expiredOffer.get().getCredentialStatus() == CredentialStatusEnum.EXPIRED;
        assert validOffer.get().getCredentialStatus() == CredentialStatusEnum.OFFERED;
    }
}
