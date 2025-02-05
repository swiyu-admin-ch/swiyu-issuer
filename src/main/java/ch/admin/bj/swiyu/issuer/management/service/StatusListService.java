/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.service;

import ch.admin.bj.swiyu.core.status.registry.client.model.StatusListEntryCreationDto;
import ch.admin.bj.swiyu.issuer.management.api.statuslist.StatusListCreateDto;
import ch.admin.bj.swiyu.issuer.management.api.statuslist.StatusListDto;
import ch.admin.bj.swiyu.issuer.management.api.statuslist.StatusListTypeDto;
import ch.admin.bj.swiyu.issuer.management.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.management.common.config.StatusListProperties;
import ch.admin.bj.swiyu.issuer.management.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.management.common.exception.ConfigurationException;
import ch.admin.bj.swiyu.issuer.management.common.exception.ResourceNotFoundException;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.CredentialOfferStatus;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.StatusList;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.StatusListRepository;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.StatusListType;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.TokenStatsListBit;
import ch.admin.bj.swiyu.issuer.management.domain.credentialoffer.TokenStatusListToken;
import ch.admin.bj.swiyu.issuer.management.service.statusregistry.StatusRegistryClient;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import static ch.admin.bj.swiyu.issuer.management.service.statusregistry.StatusListMapper.toStatusListDto;

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

    private static boolean canRevoke(StatusList statusList) {
        return switch (statusList.getType()) {
            case TOKEN_STATUS_LIST ->
                    (Integer) statusList.getConfig().get("bits") >= TokenStatsListBit.REVOKE.getValue();
        };
    }

    private static boolean canSuspend(StatusList statusList) {
        return switch (statusList.getType()) {
            case TOKEN_STATUS_LIST ->
                    (Integer) statusList.getConfig().get("bits") >= TokenStatsListBit.SUSPEND.getValue();
        };
    }

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

    @Transactional
    public void revoke(Set<CredentialOfferStatus> offerStatusSet) {
        Set<CredentialOfferStatus> revokableStatusSet = offerStatusSet.stream()
                .filter(credentialOfferStatus -> canRevoke(credentialOfferStatus.getStatusList()))
                .collect(Collectors.toSet());
        if (revokableStatusSet.isEmpty()) {
            throw new BadRequestException("No Status List which supports revocation found");
        }
        for (CredentialOfferStatus offerStatus : revokableStatusSet) {
            switch (offerStatus.getStatusList().getType()) {
                case TOKEN_STATUS_LIST -> updateTokenStatusList(offerStatus, TokenStatsListBit.REVOKE.getValue());
            }
        }
    }

    @Transactional
    public void suspend(Set<CredentialOfferStatus> offerStatusSet) {
        Set<CredentialOfferStatus> suspendableStatusSet = offerStatusSet.stream()
                .filter(credentialOfferStatus -> canSuspend(credentialOfferStatus.getStatusList()))
                .collect(Collectors.toSet());
        if (suspendableStatusSet.isEmpty()) {
            throw new BadRequestException("No Status List which supports suspension found");
        }
        for (CredentialOfferStatus offerStatus : suspendableStatusSet) {
            switch (offerStatus.getStatusList().getType()) {
                case TOKEN_STATUS_LIST -> updateTokenStatusList(offerStatus, TokenStatsListBit.SUSPEND.getValue());
            }
        }
    }

    @Transactional
    public void revalidate(Set<CredentialOfferStatus> offerStatusSet) {
        Set<CredentialOfferStatus> suspendableStatusSet = offerStatusSet.stream()
                .filter(credentialOfferStatus -> canSuspend(credentialOfferStatus.getStatusList()))
                .collect(Collectors.toSet());
        if (suspendableStatusSet.isEmpty()) {
            throw new BadRequestException("No Status List which supports suspension found");
        }
        for (CredentialOfferStatus offerStatus : suspendableStatusSet) {
            switch (offerStatus.getStatusList().getType()) {
                case TOKEN_STATUS_LIST -> updateTokenStatusList(offerStatus, TokenStatsListBit.VALID.getValue());
            }
        }
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
     * @param statusValue the statusBit to be set
     */
    private void updateTokenStatusList(CredentialOfferStatus offerStatus, int statusValue) {
        StatusList statusList = statusListRepository.findByIdForUpdate(offerStatus.getStatusList().getId()).orElseThrow();
        try {
            var token = TokenStatusListToken.loadTokenStatusListToken((Integer) statusList.getConfig().get("bits"),
                    statusList.getStatusZipped());
            token.setStatus(offerStatus.getIndex(), statusValue);
            statusList.setStatusZipped(token.getStatusListData());
            statusListRepository.save(statusList);
            updateRegistry(statusList, token);
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
