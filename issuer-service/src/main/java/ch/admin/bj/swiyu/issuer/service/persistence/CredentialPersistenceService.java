package ch.admin.bj.swiyu.issuer.service.persistence;

import ch.admin.bj.swiyu.issuer.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.common.exception.ResourceNotFoundException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.*;

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
    private final AvailableStatusListIndexRepository availableStatusListIndexRepository;
    private final Random random = new Random();

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
        return credentialOfferRepository.findByMetadataTenantId(tenantId)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "No credential offer found for tenant %s".formatted(tenantId)));
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
     * @param expireStates the states that can expire
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
     * @param expireStates the states that can expire
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
     * @param statusLists the status lists
     * @param credentialOfferId the credential offer ID
     * @param issuanceBatchSize the batch size for issuance
     */
    public void saveStatusListEntries(
            List<StatusList> statusLists,
            UUID credentialOfferId,
            int issuanceBatchSize) {

        for (StatusList statusList : statusLists) {
            Set<Integer> randomIndexes = getRandomIndexes(issuanceBatchSize, statusList);

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

    /**
     * Gets random available indexes from a status list.
     *
     * @param issuanceBatchSize the number of indexes needed
     * @param statusList the status list
     * @return a set of random available indexes
     * @throws BadRequestException if not enough indexes are available
     */
    Set<Integer> getRandomIndexes(int issuanceBatchSize, StatusList statusList) {
        // Find all free indexes for this status list
        var freeIndexes = availableStatusListIndexRepository.findById(statusList.getUri())
                .orElseThrow(() -> new BadRequestException(
                        "No status indexes remain in status list %s to create credential offer"
                                .formatted(statusList.getUri())))
                .getFreeIndexes();

        if (freeIndexes.size() < issuanceBatchSize) {
            throw new BadRequestException(
                    "Too few status indexes remain in status list %s to create credential offer"
                            .formatted(statusList.getUri()));
        }

        // Random sample free indexes without repetitions
        Set<Integer> sampledNumbers = new LinkedHashSet<>();
        while (sampledNumbers.size() < issuanceBatchSize) {
            sampledNumbers.add(freeIndexes.remove(random.nextInt(freeIndexes.size())));
        }
        return sampledNumbers;
    }
}
