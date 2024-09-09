package ch.admin.bit.eid.issuer_management.domain;

import ch.admin.bit.eid.issuer_management.domain.entities.CredentialOfferStatus;
import ch.admin.bit.eid.issuer_management.domain.entities.CredentialOfferStatusKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CredentialOfferStatusRepository extends JpaRepository<CredentialOfferStatus, CredentialOfferStatusKey> {
}
