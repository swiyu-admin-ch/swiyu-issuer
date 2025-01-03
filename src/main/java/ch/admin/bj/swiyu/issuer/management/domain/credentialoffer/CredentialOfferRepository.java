package ch.admin.bj.swiyu.issuer.management.domain.credentialoffer;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface CredentialOfferRepository extends JpaRepository<CredentialOfferEntity, UUID> {
}
