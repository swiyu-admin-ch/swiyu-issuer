package ch.admin.bj.swiyu.issuer.migration.domain;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface CredentialOfferV13Repository
        extends JpaRepository<CredentialOfferV13Entity, UUID> {
}
