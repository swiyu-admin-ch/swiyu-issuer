package ch.admin.bit.eid.issuer_management.domain;

import ch.admin.bit.eid.issuer_management.domain.entities.CredentialOffer;
import ch.admin.bit.eid.issuer_management.enums.CredentialStatusEnum;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;
import java.util.stream.Stream;

public interface CredentialOfferRepository extends JpaRepository<CredentialOffer, UUID> {
    Stream<CredentialOffer> findByCredentialStatusAndOfferExpirationTimestampLessThan(CredentialStatusEnum status, long timestampSeconds);
}
