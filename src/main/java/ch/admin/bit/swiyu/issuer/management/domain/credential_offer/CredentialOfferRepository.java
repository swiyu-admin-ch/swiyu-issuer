package ch.admin.bit.swiyu.issuer.management.domain.credential_offer;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface CredentialOfferRepository extends JpaRepository<CredentialOfferEntity, UUID> {
}
