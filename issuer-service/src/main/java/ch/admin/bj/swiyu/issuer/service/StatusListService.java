/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.core.status.registry.client.model.StatusListEntryCreationDto;
import ch.admin.bj.swiyu.issuer.api.statuslist.StatusListCreateDto;
import ch.admin.bj.swiyu.issuer.api.statuslist.StatusListDto;
import ch.admin.bj.swiyu.issuer.api.statuslist.StatusListTypeDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.StatusListProperties;
import ch.admin.bj.swiyu.issuer.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.common.exception.ConfigurationException;
import ch.admin.bj.swiyu.issuer.common.exception.ResourceNotFoundException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.service.statusregistry.StatusRegistryClient;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.io.IOException;
import java.util.*;

import static ch.admin.bj.swiyu.issuer.service.CredentialOfferMapper.toConfigurationOverride;
import static ch.admin.bj.swiyu.issuer.service.statusregistry.StatusListMapper.toStatusListDto;

@Slf4j
@AllArgsConstructor
@Service
public class StatusListService {

    private static final String BITS_FIELD_NAME = "bits";
    private final ApplicationProperties applicationProperties;
    private final StatusListProperties statusListProperties;
    private final StatusRegistryClient statusRegistryClient;
    private final StatusListRepository statusListRepository;
    private final TransactionTemplate transaction;
    private final SignatureService signatureService;
    private final CredentialOfferStatusRepository credentialOfferStatusRepository;

    @Transactional(readOnly = true)
    public StatusListDto getStatusListInformation(UUID statusListId) {
        var statusList = this.statusListRepository.findById(statusListId)
                .orElseThrow(() -> new ResourceNotFoundException(String.format("Status List %s not found", statusListId)));

        return toStatusListDto(statusList, statusList.getMaxLength() - credentialOfferStatusRepository.countByStatusListId(statusListId), statusListProperties.getVersion());
    }

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
            if (msg.toLowerCase().contains("status_list_uri_key")) {
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
     * @param statusListId the UUID of the status list to update
     * @return a {@link StatusListDto} representing the updated status list
     * @throws BadRequestException       if automatic status list synchronization is not disabled
     * @throws ResourceNotFoundException if no status list with the given id exists
     * @throws ConfigurationException    if the status payload cannot be loaded/decoded
     */
    @Transactional
    public StatusListDto updateStatusList(UUID statusListId) {
        if (!applicationProperties.isAutomaticStatusListSynchronizationDisabled()) {
            throw new BadRequestException("Automatic status list synchronization is not disabled");
        }

        StatusList statusList = statusListRepository.findByIdForUpdate(statusListId).orElseThrow(
                () -> new ResourceNotFoundException(String.format("Status list %s not found", statusListId)));

        TokenStatusListToken token;
        try {
            token = TokenStatusListToken.loadTokenStatusListToken((Integer) statusList.getConfig().get(BITS_FIELD_NAME),
                    statusList.getStatusZipped(), statusListProperties.getStatusListSizeLimit());
        } catch (IOException e) {
            throw new ConfigurationException(String.format("Failed to load status list %s", statusList.getId()), e);
        }
        statusList.setStatusZipped(token.getStatusListData());

        updateRegistry(statusList, token);

        return toStatusListDto(statusList, statusList.getMaxLength() - credentialOfferStatusRepository.countByStatusListId(statusList.getId()), statusListProperties.getVersion());
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public List<UUID> revoke(Set<CredentialOfferStatus> offerStatusSet) {
        return offerStatusSet.stream().map(credentialOfferStatus -> updateTokenStatusList(credentialOfferStatus, TokenStatusListBit.REVOKE).getId()).toList();
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public List<UUID> suspend(Set<CredentialOfferStatus> offerStatusSet) {
        return offerStatusSet.stream().map(credentialOfferStatus -> updateTokenStatusList(credentialOfferStatus, TokenStatusListBit.SUSPEND).getId()).toList();
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public List<UUID> revalidate(Set<CredentialOfferStatus> offerStatusSet) {
        return offerStatusSet.stream().map(credentialOfferStatus -> updateTokenStatusList(credentialOfferStatus, TokenStatusListBit.VALID).getId()).toList();
    }

    @Transactional
    public List<StatusList> findByUriIn(List<String> statusListUris) {
        return this.statusListRepository.findByUriIn(statusListUris);
    }

    /**
     * Updates the token status list by setting the given bit
     *
     * @param offerStatus
     * @param bit         the statusBit to be set
     */
    protected StatusList updateTokenStatusList(CredentialOfferStatus offerStatus, TokenStatusListBit bit) {
        // TODO Make updating status more efficient
        StatusList statusList = statusListRepository.findByIdForUpdate(offerStatus.getId().getStatusListId()).orElseThrow();
        var statusListBits = (Integer) statusList.getConfig().get(BITS_FIELD_NAME);
        if (statusListBits < bit.getValue()) {
            throw new BadRequestException(String.format("Attempted to update a status list %s to a status not supported %s", statusList.getUri(), bit.name()));
        }
        try {
            var token = TokenStatusListToken.loadTokenStatusListToken(statusListBits,
                    statusList.getStatusZipped(), statusListProperties.getStatusListSizeLimit());
            token.setStatus(offerStatus.getId().getIndex(), bit.getValue());
            statusList.setStatusZipped(token.getStatusListData());
            if (!applicationProperties.isAutomaticStatusListSynchronizationDisabled()) {
                updateRegistry(statusList, token);
            }
            statusListRepository.save(statusList);
            return statusList;
        } catch (IOException e) {
            log.error(String.format("Failed to load status list %s", statusList.getId()), e);
            throw new ConfigurationException(String.format("Failed to load status list %s", statusList.getId()), e);
        }
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
        updateRegistry(statusList, token);
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

    private void updateRegistry(StatusList statusListEntity, TokenStatusListToken token) {
        // Build JWT
        SignedJWT statusListJWT = buildStatusListJWT(statusListEntity, token);
        var override = statusListEntity.getConfigurationOverride();
        try {
            statusListJWT.sign(signatureService.createSigner(statusListProperties, override.keyId(), override.keyPin()));
        } catch (Exception e) {
            log.error("Failed to sign status list JWT with the provided key.", e);
            throw new ConfigurationException("Failed to sign status list JWT with the provided key.");
        }
        statusRegistryClient.updateStatusListEntry(statusListEntity, statusListJWT.serialize());
    }

    private SignedJWT buildStatusListJWT(StatusList statusListEntity, TokenStatusListToken token) {
        var override = statusListEntity.getConfigurationOverride();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(override.verificationMethodOrDefault(statusListProperties.getVerificationMethod()))
                .type(new JOSEObjectType("statuslist+jwt")).build();
        JWTClaimsSet claimSet = new JWTClaimsSet.Builder()
                .subject(statusListEntity.getUri())
                .issuer(override.issuerDidOrDefault(applicationProperties.getIssuerId()))
                .issueTime(new Date())
                .claim("status_list", token.getStatusListClaims())
                .build();
        return new SignedJWT(header, claimSet);
    }
}