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

    /**
     * Finds the UUIDs of all credential offers in the given states which are past the provided expiration timestamp.
     *
     * <p>This is a plain read: the offers are locked individually when they are expired
     * (see {@link #findByIdForUpdate(UUID)}), so no lock is taken here.</p>
     *
     * @param credentialStatus                   the offer states which may expire
     * @param offerExpirationTimestampIsLessThan the expiration timestamp
     * @return the UUIDs of the expired credential offers
     */
    @Query("SELECT o.id FROM CredentialOffer o "
            + "WHERE o.credentialStatus IN :credentialStatus "
            + "AND o.offerExpirationTimestamp < :offerExpirationTimestampIsLessThan")
    List<UUID> findExpiredOfferIds(
            Collection<CredentialOfferStatusType> credentialStatus,
            long offerExpirationTimestampIsLessThan);
}