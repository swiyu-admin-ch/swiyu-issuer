package ch.admin.bj.swiyu.issuer.management.domain.credentialofferstatus;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CredentialOfferStatusRepository
        extends JpaRepository<CredentialOfferStatusEntity, CredentialOfferStatusKey> {
}
