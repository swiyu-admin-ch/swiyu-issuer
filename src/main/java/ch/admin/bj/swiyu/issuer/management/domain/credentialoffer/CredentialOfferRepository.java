package ch.admin.bj.swiyu.issuer.management.domain.credentialoffer;

import ch.admin.bj.swiyu.issuer.management.enums.CredentialStatusEnum;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;
import java.util.stream.Stream;

public interface CredentialOfferRepository extends JpaRepository<CredentialOfferEntity, UUID> {
    Stream<CredentialOfferEntity> findByCredentialStatusAndOfferExpirationTimestampLessThan(CredentialStatusEnum status,
                                                                                            long timestampSeconds);
}
