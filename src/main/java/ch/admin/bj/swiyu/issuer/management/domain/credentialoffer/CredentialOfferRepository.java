package ch.admin.bj.swiyu.issuer.management.domain.credentialoffer;

import ch.admin.bj.swiyu.issuer.management.enums.CredentialStatusType;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;
import java.util.stream.Stream;

public interface CredentialOfferRepository extends JpaRepository<CredentialOffer, UUID> {
    Stream<CredentialOffer> findByCredentialStatusAndOfferExpirationTimestampLessThan(CredentialStatusType status,
                                                                                      long timestampSeconds);
}
