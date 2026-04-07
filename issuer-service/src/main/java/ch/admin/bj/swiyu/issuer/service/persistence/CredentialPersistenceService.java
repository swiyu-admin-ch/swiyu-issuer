package ch.admin.bj.swiyu.issuer.service.persistence;

import ch.admin.bj.swiyu.issuer.common.exception.ResourceNotFoundException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.service.statuslist.StatusListIndexService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Service responsible for credential offer persistence operations.
 *
 * <p>This service encapsulates all database operations related to credential offers,
 * credential management, and status lists, separating persistence logic from business logic.</p>
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class CredentialPersistenceService {

    private final CredentialOfferRepository credentialOfferRepository;
    private final CredentialManagementRepository credentialManagementRepository;
    private final CredentialOfferStatusRepository credentialOfferStatusRepository;
    private final StatusListIndexService statusListIndexService;

    /**
     * Saves a credential offer entity.
     *
     * @param credentialOffer the credential offer to save
     * @return the saved credential offer
     */
    public CredentialOffer saveCredentialOffer(CredentialOffer credentialOffer) {
        return credentialOfferRepository.save(credentialOffer);
    }

    /**
     * Saves a credential management entity.
     *
     * @param credentialManagement the credential management to save
     * @return the saved credential management
     */
    public CredentialManagement saveCredentialManagement(CredentialManagement credentialManagement) {
        return credentialManagementRepository.save(credentialManagement);
    }

    /**
     * Finds a credential management by ID.
     *
     * @param managementId the management ID
     * @return the credential management
     * @throws ResourceNotFoundException if not found
     */
    public CredentialManagement findCredentialManagementById(UUID managementId) {
        return credentialManagementRepository.findById(managementId)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "Credential Management %s not found".formatted(managementId)));
    }

    /**
     * Finds a credential offer by ID with pessimistic lock.
     *
     * @param credentialId the credential ID
     * @return the locked credential offer
     * @throws ResourceNotFoundException if not found
     */
    public CredentialOffer findCredentialOfferByIdForUpdate(UUID credentialId) {
        return credentialOfferRepository.findByIdForUpdate(credentialId)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "Credential %s not found".formatted(credentialId)));
    }

    /**
     * Finds a credential offer by metadata tenant ID.
     *
     * @param tenantId the tenant ID
     * @return the credential offer
     * @throws ResourceNotFoundException if not found
     */
    public CredentialOffer findCredentialOfferByMetadataTenantId(UUID tenantId) {
        var offers = credentialOfferRepository.findLatestOffersByMetadataTenantId(tenantId, PageRequest.of(0, 1));
        if (offers.isEmpty()) {
            throw new ResourceNotFoundException(
                    "No credential offer found for tenant %s".formatted(tenantId));
        }
        return offers.getFirst();
    }

    /**
     * Finds credential offer statuses by offer IDs.
     *
     * @param offerIds the offer IDs
     * @return the set of credential offer statuses
     */
    public Set<CredentialOfferStatus> findCredentialOfferStatusesByOfferIds(List<UUID> offerIds) {
        return credentialOfferStatusRepository.findByOfferIdIn(offerIds);
    }

    /**
     * Finds expired credential offers.
     *
     * @param expireStates    the states that can expire
     * @param expireTimeStamp the expiration timestamp
     * @return the list of expired offers
     */
    public List<CredentialOffer> findExpiredOffers(
            List<CredentialOfferStatusType> expireStates,
            long expireTimeStamp) {

        return credentialOfferRepository
                .findByCredentialStatusInAndOfferExpirationTimestampLessThan(expireStates, expireTimeStamp)
                .toList();
    }

    /**
     * Counts expired credential offers.
     *
     * @param expireStates    the states that can expire
     * @param expireTimeStamp the expiration timestamp
     * @return the count of expired offers
     */
    public long countExpiredOffers(
            List<CredentialOfferStatusType> expireStates,
            long expireTimeStamp) {

        return credentialOfferRepository
                .countByCredentialStatusInAndOfferExpirationTimestampLessThan(expireStates, expireTimeStamp);
    }

    /**
     * Saves status list entries for a credential offer.
     *
     * @param statusLists       the status lists
     * @param credentialOfferId the credential offer ID
     * @param issuanceBatchSize the batch size for issuance
     */
    @Transactional
    public void saveStatusListEntries(
            List<StatusList> statusLists,
            UUID credentialOfferId,
            int issuanceBatchSize) {

        // Sort by ID before locking to guarantee a consistent lock-acquisition order
        // across concurrent transactions and prevent deadlocks.
        var sortedStatusLists = statusLists.stream()
                .sorted(Comparator.comparing(StatusList::getId))
                .toList();

        for (StatusList statusList : sortedStatusLists) {

            Set<Integer> randomIndexes = statusListIndexService.claimRandomIndexes(statusList, issuanceBatchSize);

            // Create Status List entries
            var offerStatuses = randomIndexes.stream().map(freeIndex -> {
                var offerStatusKey = CredentialOfferStatusKey.builder()
                        .offerId(credentialOfferId)
                        .statusListId(statusList.getId())
                        .index(freeIndex)
                        .build();

                log.debug("Credential offer {} uses status list {} indexes {}",
                        credentialOfferId, statusList.getUri(), freeIndex);

                return CredentialOfferStatus.builder()
                        .id(offerStatusKey)
                        .build();
            }).toList();

            credentialOfferStatusRepository.saveAll(offerStatuses);
        }
    }
}
