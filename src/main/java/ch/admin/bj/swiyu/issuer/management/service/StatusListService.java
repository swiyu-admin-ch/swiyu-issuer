/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.service;

import java.io.IOException;
import java.util.*;

import static ch.admin.bj.swiyu.issuer.management.service.statusregistry.StatusListMapper.toStatusListDto;

import ch.admin.bj.swiyu.core.status.registry.client.model.StatusListEntryCreationDto;
import ch.admin.bj.swiyu.issuer.management.api.statuslist.StatusListCreateDto;
import ch.admin.bj.swiyu.issuer.management.api.statuslist.StatusListDto;
import ch.admin.bj.swiyu.issuer.management.api.statuslist.StatusListTypeDto;
import ch.admin.bj.swiyu.issuer.management.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.management.common.config.StatusListProperties;
import ch.admin.bj.swiyu.issuer.management.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.management.common.exception.ConfigurationException;
import ch.admin.bj.swiyu.issuer.management.common.exception.ResourceNotFoundException;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.management.service.statusregistry.StatusRegistryClient;
import com.nimbusds.jose.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

@Slf4j
@AllArgsConstructor
@Service
public class StatusListService {

    private final ApplicationProperties applicationProperties;
    private final StatusListProperties statusListProperties;
    private final StatusRegistryClient statusRegistryClient;
    private final StatusListRepository statusListRepository;
    private final TransactionTemplate transaction;
    private final JWSSigner signer;

    @Transactional(readOnly = true)
    public StatusListDto getStatusListInformation(UUID statusListId) {
        var statusList = this.statusListRepository.findById(statusListId)
                .orElseThrow(
                        () -> new ResourceNotFoundException(String.format("Status List %s not found", statusListId)));

        return toStatusListDto(statusList, statusListProperties.getVersion());
    }

    @Transactional
    public StatusListDto createStatusList(StatusListCreateDto request) {
        try {
            // use explicit transaction, since we want to handle data integrety exceptions
            // after commit
            var newStatusList = transaction.execute(status -> {
                var statusListType = request.getType();
                var statusList = switch (statusListType) {
                    case TOKEN_STATUS_LIST -> initTokenStatusListToken(request);
                };
                return statusListRepository.save(statusList);
            });

            return toStatusListDto(newStatusList, statusListProperties.getVersion());
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

    @Transactional(propagation = Propagation.MANDATORY)
    public void revoke(Set<CredentialOfferStatus> offerStatusSet) {
        offerStatusSet.forEach(credentialOfferStatus -> updateTokenStatusList(credentialOfferStatus, TokenStatusListBit.REVOKE));
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void suspend(Set<CredentialOfferStatus> offerStatusSet) {
        offerStatusSet.forEach(credentialOfferStatus -> updateTokenStatusList(credentialOfferStatus, TokenStatusListBit.SUSPEND));
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void revalidate(Set<CredentialOfferStatus> offerStatusSet) {
        offerStatusSet.forEach(credentialOfferStatus -> updateTokenStatusList(credentialOfferStatus, TokenStatusListBit.VALID));
    }

    @Transactional
    public List<StatusList> findByUriIn(List<String> statusListUris) {
        return this.statusListRepository.findByUriIn(statusListUris);
    }

    @Transactional
    public void incrementNextFreeIndex(UUID statusListId) {
        var statusList = statusListRepository.findByIdForUpdate(statusListId)
                .orElseThrow(() -> new BadRequestException(String.format("Status List %s not found", statusListId)));
        statusList.incrementNextFreeIndex();
        statusListRepository.save(statusList);
    }

    /**
     * Updates the token status list by setting the given bit
     *
     * @param offerStatus
     * @param bit         the statusBit to be set
     */
    private void updateTokenStatusList(CredentialOfferStatus offerStatus, TokenStatusListBit bit) {
        StatusList statusList = statusListRepository.findByIdForUpdate(offerStatus.getId().getStatusListId()).orElseThrow();
        if ((Integer) statusList.getConfig().get("bits") < bit.getValue()) {
            throw new BadRequestException(String.format("Attempted to update a status list %s to a status not supported %s", statusList.getUri(), bit.name()));
        }
        try {
            var token = TokenStatusListToken.loadTokenStatusListToken((Integer) statusList.getConfig().get("bits"),
                    statusList.getStatusZipped());
            token.setStatus(offerStatus.getIndex(), bit.getValue());
            statusList.setStatusZipped(token.getStatusListData());
            updateRegistry(statusList, token);
            statusListRepository.save(statusList);
        } catch (IOException e) {
            log.error(String.format("Failed to load status list %s", statusList.getId()), e);
            throw new ConfigurationException(String.format("Failed to load status list %s", statusList.getId()));
        }
    }

    private StatusList initTokenStatusListToken(StatusListCreateDto statusListCreateDto) {

        Map<String, Object> config = statusListCreateDto.getConfig();
        if (config == null || config.get("bits") == null) {
            throw new BadRequestException("Must define 'bits' for TokenStatusList");
        }

        // creates new empty status list entry in the registry
        var newStatusList = createEmptyRegistryEntry();

        TokenStatusListToken token = new TokenStatusListToken((Integer) config.get("bits"),
                statusListCreateDto.getMaxLength());

        // Build DB Entry
        StatusList statusList = StatusList.builder()
                .type(getStatusListTypeFromDto(statusListCreateDto.getType()))
                .config(statusListCreateDto.getConfig())
                .uri(newStatusList.getStatusRegistryUrl())
                .statusZipped(token.getStatusListData())
                .nextFreeIndex(0)
                .maxLength(statusListCreateDto.getMaxLength())
                .build();

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

        return statusRegistryClient.createStatusList();
    }

    private void updateRegistry(StatusList statusListEntity, TokenStatusListToken token) {
        // Build JWT
        SignedJWT statusListJWT = buildStatusListJWT(statusListEntity, token);

        try {
            statusListJWT.sign(signer);
        } catch (JOSEException e) {
            log.error("Failed to sign status list JWT with the provided key.", e);
            throw new ConfigurationException("Failed to sign status list JWT with the provided key.");
        }
        statusRegistryClient.updateStatusList(statusListEntity, statusListJWT.serialize());
    }

    private SignedJWT buildStatusListJWT(StatusList statusListEntity, TokenStatusListToken token) {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(statusListProperties.getVerificationMethod())
                .type(new JOSEObjectType("statuslist+jwt")).build();
        JWTClaimsSet claimSet = new JWTClaimsSet.Builder()
                .subject(statusListEntity.getUri())
                .issuer(applicationProperties.getIssuerId())
                .issueTime(new Date())
                .claim("status_list", token.getStatusListClaims())
                .build();
        return new SignedJWT(header, claimSet);
    }
}
