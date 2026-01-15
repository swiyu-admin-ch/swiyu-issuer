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

import java.io.IOException;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Service responsible for persisting status list updates to the database and registry.
 * <p>
 * This service handles the low-level operations of updating status bits in token status lists,
 * persisting changes to the database, and optionally publishing updates to the external registry.
 * </p>
 *
 * @author pgatschet
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
        return offerStatusSet.stream()
                .map(credentialOfferStatus -> updateTokenStatusList(credentialOfferStatus, TokenStatusListBit.REVOKE).getId())
                .toList();
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
        return offerStatusSet.stream()
                .map(credentialOfferStatus -> updateTokenStatusList(credentialOfferStatus, TokenStatusListBit.SUSPEND).getId())
                .toList();
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
        return offerStatusSet.stream()
                .map(credentialOfferStatus -> updateTokenStatusList(credentialOfferStatus, TokenStatusListBit.VALID).getId())
                .toList();
    }

    /**
     * Updates the token status list by setting the given bit for a specific credential offer status.
     *
     * @param offerStatus the credential offer status containing the status list reference
     * @param bit the status bit to set (VALID, REVOKE, or SUSPEND)
     * @return the updated status list
     * @throws ResourceNotFoundException if the status list cannot be found
     * @throws ConfigurationException if the status list cannot be loaded or updated
     */
    private StatusList updateTokenStatusList(CredentialOfferStatus offerStatus, TokenStatusListBit bit) {

        UUID statusListId = offerStatus.getId().getStatusListId();
        StatusList statusList = statusListRepository.findByIdForUpdate(statusListId)
                .orElseThrow(() -> new ResourceNotFoundException(String.format("Status list %s not found", statusListId)));

        var statusListBits = (Integer) statusList.getConfig().get(BITS_FIELD_NAME);
        StatusListValidator.requireBitSupported(statusListBits, bit, statusList.getUri());

        try {
            var token = TokenStatusListToken.loadTokenStatusListToken(statusListBits,
                    statusList.getStatusZipped(), statusListProperties.getStatusListSizeLimit());
            token.setStatus(offerStatus.getId().getIndex(), bit.getValue());
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
    private void publishToRegistry(StatusList statusListEntity, TokenStatusListToken token) {
        SignedJWT jwt = signingService.buildSignedStatusListJwt(statusListEntity, token);
        statusRegistryClient.updateStatusListEntry(statusListEntity, jwt.serialize());
    }
}

