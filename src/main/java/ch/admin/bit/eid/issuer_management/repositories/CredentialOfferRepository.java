package ch.admin.bit.eid.issuer_management.repositories;

import ch.admin.bit.eid.issuer_management.models.entities.CredentialOfferEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface CredentialOfferRepository extends JpaRepository<CredentialOfferEntity, UUID> {
}
