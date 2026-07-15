package ch.admin.bj.swiyu.issuer.service.statuslist;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.StatusListProperties;
import ch.admin.bj.swiyu.issuer.common.exception.ConfigurationException;
import ch.admin.bj.swiyu.issuer.common.exception.ResourceNotFoundException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.service.statusregistry.StatusRegistryClient;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import java.io.IOException;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Service responsible for persisting status list updates to the database and registry.
 * <p>
 * This service handles the low-level operations of updating status bits in token status lists,
 * persisting changes to the database, and optionally publishing updates to the external registry.
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
        return updateTokenStatusList(offerStatusSet, TokenStatusListBit.REVOKE).stream()
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
        return updateTokenStatusList(offerStatusSet, TokenStatusListBit.SUSPEND).stream()
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
     * @param offerStatus set of the credential offer status containing the status list reference to be updated
     * @param bit         the status bit to set (VALID, REVOKE, or SUSPEND)
     * @return the updated status lists
     * @throws ResourceNotFoundException if the status list cannot be found
     * @throws ConfigurationException    if the status list cannot be loaded or updated
     */
    private List<StatusList> updateTokenStatusList(Set<CredentialOfferStatus> offerStatus, TokenStatusListBit bit) {

        Map<UUID, List<Integer>> statusListIds = groupAffectedStatusListIndexes(offerStatus);
        List<StatusList> updated = new ArrayList<>(statusListIds.size());
        List<StatusListRegistryUpdate> registryUpdates = new ArrayList<>();

        // Bulk load + lock to avoid one SELECT ... FOR UPDATE per statusListId
        List<UUID> ids = List.copyOf(statusListIds.keySet());
        Map<UUID, StatusList> statusListsById = statusListRepository.findAllByIdInForUpdate(ids).stream()
                .collect(Collectors.toMap(StatusList::getId, Function.identity()));

        for (Map.Entry<UUID, List<Integer>> entry : statusListIds.entrySet()) {
            UUID statusListId = entry.getKey();

            StatusList statusList = statusListsById.get(statusListId);

            // ensure status list is present
            if (statusList == null) {
                throw new ResourceNotFoundException(String.format("Status list %s not found", statusListId));
            }

            var statusListBits = (Integer) statusList.getConfig().get(BITS_FIELD_NAME);
            StatusListValidator.requireBitSupported(statusListBits, bit, statusList.getUri());

            try {
                var token = TokenStatusListToken.loadTokenStatusListToken(statusListBits,
                        statusList.getStatusZipped(), statusListProperties.getStatusListSizeLimit());

                for (int index : entry.getValue()) {
                    token.setStatus(index, bit.getValue());
                }

                statusList.setStatusZipped(token.getStatusListData());
                updated.add(statusList);

                // Prepare registry update if enabled
                if (!applicationProperties.isAutomaticStatusListSynchronizationDisabled()) {
                    registryUpdates.add(new StatusListRegistryUpdate(statusList, token));
                }
            } catch (IOException e) {
                log.error("Failed to load status list {}", statusList.getId(), e);
                throw new ConfigurationException(String.format("Failed to load status list %s", statusList.getId()), e);
            }
        }

        // Batch save all updates
        statusListRepository.saveAll(updated);

        // Publish to registry after successful save
        if (!registryUpdates.isEmpty()) {
            publishUpdatesToRegistry(registryUpdates);
        }

        return updated;
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
     * Publishes the status list to the external registry.
     *
     * @param update the status list update containing the status list entity and the token
     */
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void publishToRegistry(StatusListPersistenceService.StatusListRegistryUpdate update) {
        SignedJWT jwt = signingService.buildSignedStatusListJwt(update.statusList(), update.token());
        statusRegistryClient.updateStatusListEntry(update.statusList(), jwt.serialize());
    }

    /**
     * Publishes the status list to the external registry.
     *
     * @param updates the list of status list updates
     */
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void publishUpdatesToRegistry(List<StatusListPersistenceService.StatusListRegistryUpdate> updates) {
        for (StatusListRegistryUpdate update : updates) {
            SignedJWT jwt = signingService.buildSignedStatusListJwt(update.statusList(), update.token());
            statusRegistryClient.updateStatusListEntry(update.statusList(), jwt.serialize());
        }
    }

    public record StatusListRegistryUpdate(StatusList statusList, TokenStatusListToken token) {
    }
}
