package ch.admin.bit.eid.issuer_management.domain;

import ch.admin.bit.eid.issuer_management.domain.entities.CredentialOffer;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface CredentialOfferRepository extends JpaRepository<CredentialOffer, UUID> {
}
