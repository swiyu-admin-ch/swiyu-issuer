package ch.admin.bj.swiyu.issuer.service.statuslist;

import ch.admin.bj.swiyu.core.status.registry.client.model.StatusListEntryCreationDto;
import ch.admin.bj.swiyu.issuer.common.config.StatusListProperties;
import ch.admin.bj.swiyu.issuer.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.common.exception.ConfigurationException;
import ch.admin.bj.swiyu.issuer.common.exception.ResourceNotFoundException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.dto.common.ConfigurationOverrideDto;
import ch.admin.bj.swiyu.issuer.dto.credentialoffer.CreateCredentialOfferRequestDto;
import ch.admin.bj.swiyu.issuer.dto.statuslist.StatusListCreateDto;
import ch.admin.bj.swiyu.issuer.dto.statuslist.StatusListDto;
import ch.admin.bj.swiyu.issuer.dto.statuslist.StatusListTypeDto;
import ch.admin.bj.swiyu.issuer.service.statusregistry.StatusRegistryClient;
import jakarta.annotation.Nullable;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static ch.admin.bj.swiyu.issuer.service.offer.CredentialOfferMapper.mergeConfigurationOverride;
import static ch.admin.bj.swiyu.issuer.service.offer.CredentialOfferMapper.toConfigurationOverride;
import static ch.admin.bj.swiyu.issuer.service.statuslist.StatusListMapper.toStatusListDto;

/**
 * Orchestrates all operations related to status lists, including creation, update, validation,
 * and synchronization with the external status registry.
 * <p>
 * <b>Responsibilities:</b>
 * <ul>
 *   <li>Creates and persists new status lists, and publishes them to the status registry.</li>
 *   <li>Updates status lists and synchronizes changes with the external registry.</li>
 *   <li>Handles post-issuance status changes (revoke, suspend, revalidate) for credentials via the persistence service.</li>
 *   <li>Resolves and validates status lists for credential offer requests.</li>
 *   <li>Ensures transactional integrity and consistency between the database and registry.</li>
 * </ul>
 * <p>
 * <b>Workflow:</b>
 * <ul>
 *   <li>Coordinates between repository, signing, and registry services for status list lifecycle management.</li>
 *   <li>Uses explicit transactions for creation to handle integrity exceptions after commit.</li>
 *   <li>Delegates low-level status bit updates to {@link StatusListPersistenceService}.</li>
 *   <li>Publishes status list changes to the registry when required.</li>
 * </ul>
 * <p>
 * <b>Transactional Boundaries:</b>
 * <ul>
 *   <li>Read-only for information and resolution queries.</li>
 *   <li>Transactional for creation and update operations.</li>
 * </ul>
 *
 * <b>Note:</b> This class acts as a coordinator/facade, managing workflows that involve multiple services,
 * repositories, and transactional boundaries for status list management. It does not perform low-level
 * status bit manipulations directly.
 *
 * @author pgatschet
 */
@Slf4j
@AllArgsConstructor
@Service
public class StatusListOrchestrator {

    private static final String BITS_FIELD_NAME = "bits";
    private final StatusListProperties statusListProperties;

    private final StatusRegistryClient statusRegistryClient;
    private final StatusListPersistenceService statusListPersistenceService;

    private final StatusListRepository statusListRepository;
    private final TransactionTemplate transaction;
    private final CredentialOfferStatusRepository credentialOfferStatusRepository;


    /**
     * Returns status list metadata for the given status list id.
     *
     * @param statusListId status list id
     * @return status list information (including currently available capacity)
     * @throws ResourceNotFoundException if the status list does not exist
     */
    @Transactional(readOnly = true)
    public StatusListDto getStatusListInformation(UUID statusListId) {
        var statusList = this.statusListRepository.findById(statusListId)
                .orElseThrow(() -> new ResourceNotFoundException(String.format("Status List %s not found", statusListId)));

        return toStatusListDto(statusList,
                statusList.getMaxLength() - credentialOfferStatusRepository.countByStatusListId(statusListId),
                statusListProperties.getVersion());
    }

    /**
     * Creates a new status list, persists it, and publishes the initial entry to the status registry.
     *
     * @param request create request
     * @return the created status list
     * @throws BadRequestException if a status list with the same URI already exists
     */
    @Transactional
    public StatusListDto createStatusList(StatusListCreateDto request) {
        try {
            // use explicit transaction, since we want to handle data integrity exceptions
            // after commit
            var newStatusList = transaction.execute(status -> {
                var statusListType = request.getType();
                var statusList = switch (statusListType) {
                    case TOKEN_STATUS_LIST -> initTokenStatusListToken(request);
                };
                return statusListRepository.save(statusList);
            });

            return toStatusListDto(newStatusList, newStatusList.getMaxLength(), statusListProperties.getVersion());
        } catch (DataIntegrityViolationException e) {
            var msg = e.getMessage();
            if (msg != null && msg.toLowerCase().contains("status_list_uri_key")) {
                log.debug("Statuslist could not be initialized since already initialized", e);
                throw new BadRequestException("Status list already initialized");
            } else {
                throw e;
            }
        }
    }

    /**
     * Updates the status list identified by {@code statusListId} and synchronizing
     * the entry with the external status registry.
     *
     * <p>The method enforces that automatic status list synchronization is enabled by default in the
     * application configuration.</p>
     *
     * <p>If {@code overrideDto} is provided, it is merged into the existing stored configuration override
     * (non-null fields take precedence) and then persisted on the status list. From that point onward,
     * subsequent status list publications will use the updated override (e.g., for key material selection).</p>
     *
     * @param statusListId the UUID of the status list to update
     * @param overrideDto  optional configuration override to be stored on the status list
     * @return a {@link StatusListDto} representing the updated status list
     * @throws BadRequestException       if automatic status list synchronization is not disabled
     * @throws ResourceNotFoundException if no status list with the given id exists
     * @throws ConfigurationException    if the status payload cannot be loaded/decoded
     */
    @Transactional
    public StatusListDto updateStatusList(UUID statusListId, @Nullable ConfigurationOverrideDto overrideDto) {

        StatusList statusList = statusListRepository.findByIdForUpdate(statusListId).orElseThrow(
                () -> new ResourceNotFoundException(String.format("Status list %s not found", statusListId)));

        TokenStatusListToken token = loadTokenStatusListToken(statusList);
        statusList.setStatusZipped(token.getStatusListData());

        mergeAndPersistConfigurationOverrideIfPresent(overrideDto, statusList);

        statusListPersistenceService.publishToRegistry(statusList, token);

        return toStatusListDto(statusList,
                statusList.getMaxLength() - credentialOfferStatusRepository.countByStatusListId(statusList.getId()),
                statusListProperties.getVersion());
    }

    private void mergeAndPersistConfigurationOverrideIfPresent(@Nullable ConfigurationOverrideDto overrideDto, StatusList statusList) {
        if (overrideDto != null) {
            var mergedOverride = mergeConfigurationOverride(statusList.getConfigurationOverride(),
                    toConfigurationOverride(overrideDto));
            statusList.setConfigurationOverride(mergedOverride);
            // Persist local changes (status + optional override) before publishing.
            statusListRepository.save(statusList);
        }
    }

    private TokenStatusListToken loadTokenStatusListToken(StatusList statusList) {
        try {
            return TokenStatusListToken.loadTokenStatusListToken(
                    (Integer) statusList.getConfig().get(BITS_FIELD_NAME),
                    statusList.getStatusZipped(),
                    statusListProperties.getStatusListSizeLimit()
            );
        } catch (IOException e) {
            throw new ConfigurationException(String.format("Failed to load status list %s", statusList.getId()), e);
        }
    }

    /**
     * Loads status lists by URI.
     *
     * @param statusListUris status list registry URIs
     * @return resolved status lists (may be fewer than requested)
     */
    @Transactional(readOnly = true)
    public List<StatusList> findByUriIn(List<String> statusListUris) {
        return this.statusListRepository.findByUriIn(statusListUris);
    }

    /**
     * Resolves and validates status lists from a credential offer request.
     *
     * @param request the credential offer request
     * @return the list of resolved status lists
     * @throws BadRequestException if not all status lists can be resolved
     */
    @Transactional(readOnly = true)
    public List<StatusList> resolveAndValidateStatusLists(CreateCredentialOfferRequestDto request) {
        var statusLists = findByUriIn(request.getStatusLists());
        return StatusListValidator.requireAllStatusListsResolved(request, statusLists);
    }


    private StatusList initTokenStatusListToken(StatusListCreateDto statusListCreateDto) {

        var config = statusListCreateDto.getConfig();

        // creates new empty status list entry in the registry
        var newStatusList = createEmptyRegistryEntry();

        TokenStatusListToken token = new TokenStatusListToken(config.getBits(),
                statusListCreateDto.getMaxLength());

        // Build DB Entry
        StatusList statusList = StatusList.builder()
                .type(getStatusListTypeFromDto(statusListCreateDto.getType()))
                .config(Map.of(
                        BITS_FIELD_NAME, config.getBits(),
                        "purpose", config.getPurpose() != null ? config.getPurpose() : ""
                ))
                .uri(newStatusList.getStatusRegistryUrl())
                .statusZipped(token.getStatusListData())
                .maxLength(statusListCreateDto.getMaxLength())
                .configurationOverride(toConfigurationOverride(statusListCreateDto.getConfigurationOverride()))
                .build();
        log.debug("Initializing new status list with bit {} per entry and {} entries to a total size of {} bit", config.getBits(), statusList.getMaxLength(), config.getBits() * statusList.getMaxLength());

        statusListPersistenceService.publishToRegistry(statusList, token);
        return statusList;
    }

    private StatusListType getStatusListTypeFromDto(StatusListTypeDto statusListTypeDto) {
        if (statusListTypeDto == null) {
            return null;
        }

        return StatusListType.TOKEN_STATUS_LIST;
    }

    private StatusListEntryCreationDto createEmptyRegistryEntry() {
        return statusRegistryClient.createStatusListEntry();
    }

}
