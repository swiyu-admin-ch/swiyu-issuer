package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import jakarta.persistence.LockModeType;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;

@Repository
public interface CredentialOfferRepository extends JpaRepository<CredentialOffer, UUID> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<CredentialOffer> findByPreAuthorizedCode(UUID uuid);

    /**
     * Find the latest created CredentialOffer by the tenantId.
     *
     * @param tenantId the unique identifier of the tenant
     * @param pageable Page 
     * @return the latest CredentialOffer Optional is empty if no CredentialOffer is found
     */
    @Query("SELECT o FROM CredentialManagement m RIGHT JOIN m.credentialOffers o WHERE m.metadataTenantId = :tenantId ORDER BY o.auditMetadata.createdAt DESC")
    List<CredentialOffer> findLatestOffersByMetadataTenantId(UUID tenantId, Pageable pageable);

    @Query("SELECT c FROM CredentialOffer c WHERE :uuid = c.id")
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<CredentialOffer> findByIdForUpdate(UUID uuid);

    long countByCredentialStatusInAndOfferExpirationTimestampLessThan(Collection<CredentialOfferStatusType> credentialStatuses, long offerExpirationTimestampIsLessThan);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Stream<CredentialOffer> findByCredentialStatusInAndOfferExpirationTimestampLessThan(Collection<CredentialOfferStatusType> credentialStatuses, long offerExpirationTimestampIsLessThan);
}