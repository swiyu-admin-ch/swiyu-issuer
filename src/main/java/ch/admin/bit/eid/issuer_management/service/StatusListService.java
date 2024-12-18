package ch.admin.bit.eid.issuer_management.service;

import ch.admin.bit.eid.issuer_management.config.ApplicationProperties;
import ch.admin.bit.eid.issuer_management.config.StatusListProperties;
import ch.admin.bit.eid.issuer_management.domain.StatusListRepository;
import ch.admin.bit.eid.issuer_management.domain.ecosystem.StatusRegistryClient;
import ch.admin.bit.eid.issuer_management.domain.entities.CredentialOfferStatus;
import ch.admin.bit.eid.issuer_management.domain.entities.StatusList;
import ch.admin.bit.eid.issuer_management.exception.BadRequestException;
import ch.admin.bit.eid.issuer_management.exception.ConfigurationException;
import ch.admin.bit.eid.issuer_management.api.dto.StatusListCreateDto;
import ch.admin.bit.eid.issuer_management.models.statuslist.TokenStatsListBit;
import ch.admin.bit.eid.issuer_management.models.statuslist.TokenStatusListToken;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
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

@Slf4j
@AllArgsConstructor
@Service
public class StatusListService {

    private final ApplicationProperties applicationProperties;
    private final StatusListProperties statusListProperties;
    private final StatusRegistryClient statusRegistryClient;
    private final StatusListRepository statusListRepository;
    private final TransactionTemplate transaction;

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

    public void createStatusList(StatusListCreateDto request) {
        try {
            // use explicit transaction, since we want to handle data integrety exceptions after commit
            transaction.executeWithoutResult((status) -> {
                var statusListType = request.getType();
                var statusList = switch (statusListType) {
                    case TOKEN_STATUS_LIST -> initTokenStatusListToken(request);
                };
                statusListRepository.save(statusList);
            });
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
        Set<CredentialOfferStatus> revokableStatusSet = offerStatusSet.stream().filter(credentialOfferStatus -> canRevoke(credentialOfferStatus.getStatusList())).collect(Collectors.toSet());
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
        Set<CredentialOfferStatus> suspendableStatusSet = offerStatusSet.stream().filter(credentialOfferStatus -> canSuspend(credentialOfferStatus.getStatusList())).collect(Collectors.toSet());
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
        Set<CredentialOfferStatus> suspendableStatusSet = offerStatusSet.stream().filter(credentialOfferStatus -> canSuspend(credentialOfferStatus.getStatusList())).collect(Collectors.toSet());
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
        var statusList = statusListRepository.findById(statusListId)
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
        StatusList statusList = offerStatus.getStatusList();
        try {
            var token = TokenStatusListToken.loadTokenStatusListToken((Integer) statusList.getConfig().get("bits"), statusList.getStatusZipped());
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

        // check upfront if the status list already exists (yes we have unique constraint, but otherwise
        // hibernate spams the log)
        if (statusListRepository.existsByUri(statusListCreateDto.getUri())) {
            throw new BadRequestException("Status List already exists with uri " + statusListCreateDto.getUri());
        }

        TokenStatusListToken token = new TokenStatusListToken((Integer) config.get("bits"), statusListCreateDto.getMaxLength());

        // Build DB Entry
        StatusList statusList = StatusList.builder()
                .type(statusListCreateDto.getType())
                .config(statusListCreateDto.getConfig())
                .uri(statusListCreateDto.getUri())
                .statusZipped(token.getStatusListData())
                .nextFreeIndex(0)
                .maxLength(statusListCreateDto.getMaxLength())
                .build();

        updateRegistry(statusList, token);
        return statusList;
    }

    private void updateRegistry(StatusList statusListEntity, TokenStatusListToken token) {
        // Build JWT
        ECKey signingKey = statusListProperties.getStatusListKey().toECKey();

        SignedJWT statusListJWT = buildStatusListJWT(statusListEntity, token);

        try {
            statusListJWT.sign(new ECDSASigner(signingKey));
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
