package ch.admin.bj.swiyu.issuer.service.statuslist;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.StatusListProperties;
import ch.admin.bj.swiyu.issuer.common.exception.ConfigurationException;
import ch.admin.bj.swiyu.issuer.common.exception.ResourceNotFoundException;

import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatus;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusKey;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusList;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusListRepository;
import ch.admin.bj.swiyu.issuer.service.statusregistry.StatusRegistryClient;
import ch.admin.bj.swiyu.statuslist.TokenStatusList;
import ch.admin.bj.swiyu.statuslist.TokenStatusListBit;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Service responsible for persisting status list updates to the database and registry.
 * <p>
 * This service handles the low-level operations of updating status bits in token status lists,
 * persisting changes to the database, and optionally publishing updates to the external registry.
 * Local changes are always written to the database before they are published, so database failures
 * abort the operation before the registry is updated and registry failures roll the local changes back.
 * </p>
 */
@Slf4j
@RequiredArgsConstructor
@Service
public class StatusListPersistenceService {

    private static final String BITS_FIELD_NAME = "bits";

    private final ApplicationProperties applicationProperties;
    private final StatusListProperties statusListProperties;
    private final StatusListRepository statusListRepository;
    private final StatusRegistryClient statusRegistryClient;
    private final StatusListSigningService signingService;

    /**
     * Marks the given credential entries as revoked in their respective status lists.
     *
     * @param offerStatusSet credential status entries to update
     * @return ids of the affected status lists
     * @throws ResourceNotFoundException if a status list cannot be found
     * @throws ConfigurationException    if the status list cannot be loaded or updated
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public List<UUID> revoke(Set<CredentialOfferStatus> offerStatusSet) {
        StatusListValidator.requireOfferStatusesPresent(offerStatusSet);
        return updateTokenStatusList(offerStatusSet, TokenStatusListBit.REVOKED).stream()
                .map(StatusList::getId).toList();
    }

    /**
     * Marks the given credential entries as suspended in their respective status lists.
     *
     * @param offerStatusSet credential status entries to update
     * @return ids of the affected status lists
     * @throws ResourceNotFoundException if a status list cannot be found
     * @throws ConfigurationException    if the status list cannot be loaded or updated
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public List<UUID> suspend(Set<CredentialOfferStatus> offerStatusSet) {
        StatusListValidator.requireOfferStatusesPresent(offerStatusSet);
        return updateTokenStatusList(offerStatusSet, TokenStatusListBit.SUSPENDED).stream()
                .map(StatusList::getId).toList();
    }

    /**
     * Marks the given credential entries as valid (re-validated) in their respective status lists.
     *
     * @param offerStatusSet credential status entries to update
     * @return ids of the affected status lists
     * @throws ResourceNotFoundException if a status list cannot be found
     * @throws ConfigurationException    if the status list cannot be loaded or updated
     */
    @Transactional(propagation = Propagation.MANDATORY)
    public List<UUID> revalidate(Set<CredentialOfferStatus> offerStatusSet) {
        StatusListValidator.requireOfferStatusesPresent(offerStatusSet);
        return updateTokenStatusList(offerStatusSet, TokenStatusListBit.VALID).stream()
                .map(StatusList::getId).toList();
    }

    /**
     * Updates the token status lists by setting the given bit for the credential offer statuses provided.
     *
     * <p>The local state is written and flushed to the database <em>before</em> the external status registry is
     * updated. This ordering guarantees that:</p>
     * <ul>
     *   <li>a database error aborts the operation before any remote state is changed, and</li>
     *   <li>a registry error fails the transactional operation, rolling back the local changes.</li>
     * </ul>
     *
     * @param offerStatus set of the credential offer status containing the status list reference to be updated
     * @param bit         the status bit to set (VALID, REVOKE, or SUSPEND)
     * @return the updated status lists
     * @throws ResourceNotFoundException if the status list cannot be found
     * @throws ConfigurationException    if the status list cannot be loaded or updated
     */
    private List<StatusList> updateTokenStatusList(Set<CredentialOfferStatus> offerStatus, TokenStatusListBit bit) {

        Map<UUID, List<Integer>> statusListIds = groupAffectedStatusListIndexes(offerStatus);

        // Bulk load + lock to avoid one SELECT ... FOR UPDATE per statusListId
        List<UUID> ids = List.copyOf(statusListIds.keySet());
        Map<UUID, StatusList> statusListsById = statusListRepository.findAllByIdInForUpdate(ids).stream()
                .collect(Collectors.toMap(StatusList::getId, Function.identity()));

        // ensure all are present
        for (UUID id : ids) {
            if (!statusListsById.containsKey(id)) {
                throw new ResourceNotFoundException(String.format("Status list %s not found", id));
            }
        }

        List<UpdatedStatusList> updated = statusListIds.entrySet()
                .stream()
                .map(statusListEntry -> updateStatusList(bit, statusListsById.get(statusListEntry.getKey()), statusListEntry.getValue()))
                .toList();

        // Write the local state first. Flushing here surfaces database errors before the remote registry is
        // touched, so a failed write can never leave the registry with data that does not exist locally.
        // One repository call instead of save() per status list
        statusListRepository.saveAllAndFlush(updated.stream()
                .map(UpdatedStatusList::statusList)
                .toList());

        // Only synchronize the registry once the local changes are written. If a registry update fails, the
        // exception fails the surrounding transaction and the database changes above are rolled back.
        if (!applicationProperties.isAutomaticStatusListSynchronizationDisabled()) {
            updated.forEach(statusList -> publishToRegistry(statusList.statusList(), statusList.token()));
        }

        return updated.stream()
                .map(UpdatedStatusList::statusList)
                .toList();
    }

    /**
     * Groups the affected status list indexes by status list id.
     *
     * @param offerStatus the offer statuses to be grouped
     * @return a map with status list ids as keys and the affected indexes as values
     */
    private Map<UUID, List<Integer>> groupAffectedStatusListIndexes(Set<CredentialOfferStatus> offerStatus) {
        return offerStatus.stream()
                .map(CredentialOfferStatus::getId)
                .collect(Collectors.groupingBy(
                        CredentialOfferStatusKey::getStatusListId,
                        Collectors.collectingAndThen(
                                Collectors.mapping(CredentialOfferStatusKey::getIndex, Collectors.toSet()),
                                List::copyOf)));
    }

    /**
     * Updates a single already-loaded status list by applying {@code bit} to all {@code affectedIndexes}.
     *
     * <p>This method only mutates the in-memory state. Persisting and publishing to the registry are the
     * responsibility of the caller so that the local database is always written before the remote registry.</p>
     *
     * @param bit             the status bit to apply (VALID, REVOKE, or SUSPEND)
     * @param statusList      the status list to update
     * @param affectedIndexes the indexes within the status list to update
     * @return the updated status list and its token
     */
    private UpdatedStatusList updateStatusList(TokenStatusListBit bit, StatusList statusList, List<Integer> affectedIndexes) {
        var statusListBits = (Integer) statusList.getConfig().get(BITS_FIELD_NAME);
        StatusListValidator.requireBitSupported(statusListBits, bit, statusList.getUri());

        try {
            var token = TokenStatusList.loadTokenStatusListToken(statusListBits,
                    statusList.getStatusZipped(), statusListProperties.getStatusListSizeLimit());
            for (int index : affectedIndexes) {
                token.setStatus(index, bit.getBitNumber());
            }
            statusList.setStatusZipped(token.getStatusListData());
            return new UpdatedStatusList(statusList, token);
        } catch (IOException e) {
            log.error("Failed to load status list {}", statusList.getId(), e);
            throw new ConfigurationException(String.format("Failed to load status list %s", statusList.getId()), e);
        }
    }

    /**
     * Publishes the status list to the external registry.
     *
     * @param statusListEntity the status list entity
     * @param token            the token status list token containing the current status data
     */
    public void publishToRegistry(StatusList statusListEntity, TokenStatusList token) {
        SignedJWT jwt = signingService.buildSignedStatusListJwt(statusListEntity, token);
        statusRegistryClient.updateStatusListEntry(statusListEntity, jwt.serialize());
    }

    /**
     * Helper record: A status list together with the token whose bits have been updated but not yet published.
     */
    private record UpdatedStatusList(StatusList statusList, TokenStatusList token) {
    }
}
