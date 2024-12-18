package ch.admin.bit.swiyu.issuer.management.domain.credential_offer_status;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CredentialOfferStatusRepository extends JpaRepository<CredentialOfferStatusEntity, CredentialOfferStatusKey> {
}
