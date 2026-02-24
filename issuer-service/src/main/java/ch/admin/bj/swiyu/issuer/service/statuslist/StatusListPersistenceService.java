package ch.admin.bj.swiyu.issuer.service.statuslist;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import com.nimbusds.jwt.SignedJWT;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.StatusListProperties;
import ch.admin.bj.swiyu.issuer.common.exception.ConfigurationException;
import ch.admin.bj.swiyu.issuer.common.exception.ResourceNotFoundException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatus;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusKey;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusList;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusListRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.TokenStatusListBit;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.TokenStatusListToken;
import ch.admin.bj.swiyu.issuer.service.statusregistry.StatusRegistryClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

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
     * @throws ConfigurationException if the status list cannot be loaded or updated
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
     * @throws ConfigurationException if the status list cannot be loaded or updated
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
     * @throws ConfigurationException if the status list cannot be loaded or updated
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
     * @param bit the status bit to set (VALID, REVOKE, or SUSPEND)
     * @return the updated status lists
     * @throws ResourceNotFoundException if the status list cannot be found
     * @throws ConfigurationException if the status list cannot be loaded or updated
     */
    private List<StatusList> updateTokenStatusList(Set<CredentialOfferStatus> offerStatus, TokenStatusListBit bit) {

        Map<UUID, List<Integer>> statusListIds = groupAffectedStatusListIndexes(offerStatus);
        
        return statusListIds.entrySet()
            .stream()
            .map(statusListEntry -> updateStatusList(bit, statusListEntry.getKey(), statusListEntry.getValue()))
            .toList();
    }

    /**
     * @param offerStatus the offer statuses to be grouped
     * @return A map with StatusList Ids as keys with all indexes affected indexes as value 
     */
    private Map<UUID, List<Integer>> groupAffectedStatusListIndexes(Set<CredentialOfferStatus> offerStatus) {
        List<CredentialOfferStatusKey> statusKeys = offerStatus.stream()
            .map(CredentialOfferStatus::getId)
            .toList();
        Map<UUID, List<Integer>> statusListIds = statusKeys.stream()
            .map(CredentialOfferStatusKey::getStatusListId)
            .collect(Collectors.toSet()).stream() // Remove duplicate IDs to be used as keys for the map
            .collect(Collectors.toMap(
                Function.identity(), 
                statusListId -> statusKeys.stream()
                    .filter(statusListKey -> statusListKey.getStatusListId().equals(statusListId))
                    .map(CredentialOfferStatusKey::getIndex).toList()));
        return statusListIds;
    }

    /**
     * 
     * @param bit the target value of the bits
     * @param statusListId the id of the status list to be updated
     * @param affectedIndexes indexes to be set to the status bit
     * @return the updated Status List
     */
    private StatusList updateStatusList(TokenStatusListBit bit, UUID statusListId, List<Integer> affectedIndexes) {
        StatusList statusList = statusListRepository.findByIdForUpdate(statusListId)
            .orElseThrow(() -> new ResourceNotFoundException(String.format("Status list %s not found", statusListId)));
        var statusListBits = (Integer) statusList.getConfig().get(BITS_FIELD_NAME);
        StatusListValidator.requireBitSupported(statusListBits, bit, statusList.getUri());

        try {
            var token = TokenStatusListToken.loadTokenStatusListToken(statusListBits,
                    statusList.getStatusZipped(), statusListProperties.getStatusListSizeLimit());
            for(int index : affectedIndexes) {
                token.setStatus(index, bit.getValue());
            }
            statusList.setStatusZipped(token.getStatusListData());
            if (!applicationProperties.isAutomaticStatusListSynchronizationDisabled()) {
                publishToRegistry(statusList, token);
            }
            statusListRepository.save(statusList);
            return statusList;
        } catch (IOException e) {
            log.error("Failed to load status list {}", statusList.getId(), e);
            throw new ConfigurationException(String.format("Failed to load status list %s", statusList.getId()), e);
        }
    }

    /**
     * Publishes the status list to the external registry.
     *
     * @param statusListEntity the status list entity
     * @param token the token status list token containing the current status data
     */
    public void publishToRegistry(StatusList statusListEntity, TokenStatusListToken token) {
        SignedJWT jwt = signingService.buildSignedStatusListJwt(statusListEntity, token);
        statusRegistryClient.updateStatusListEntry(statusListEntity, jwt.serialize());
    }
}

