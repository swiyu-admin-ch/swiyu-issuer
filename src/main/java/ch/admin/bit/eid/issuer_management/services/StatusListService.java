package ch.admin.bit.eid.issuer_management.services;

import ch.admin.bit.eid.issuer_management.config.ApplicationProperties;
import ch.admin.bit.eid.issuer_management.config.StatusListProperties;
import ch.admin.bit.eid.issuer_management.domain.StatusListRepository;
import ch.admin.bit.eid.issuer_management.domain.entities.CredentialOfferStatus;
import ch.admin.bit.eid.issuer_management.domain.entities.StatusList;
import ch.admin.bit.eid.issuer_management.exceptions.BadRequestException;
import ch.admin.bit.eid.issuer_management.exceptions.ConfigurationException;
import ch.admin.bit.eid.issuer_management.exceptions.NotImplementedError;
import ch.admin.bit.eid.issuer_management.models.dto.StatusListCreateDto;
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

import java.io.IOException;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Service
@AllArgsConstructor
public class StatusListService {

    private final ApplicationProperties applicationProperties;
    private final StatusListProperties statusListProperties;
    private final TemporaryStatusListRestClientService temporaryStatusListRestClientService;
    private final StatusListRepository statusListRepository;

    public void createStatusList(StatusListCreateDto statusListCreateDto) {
        var statusListType = statusListCreateDto.getType();
        StatusList statusList = switch (statusListType) {
            case TOKEN_STATUS_LIST -> initTokenStatusListToken(statusListCreateDto);
            default ->
                    throw new NotImplementedError(String.format("Status List Type %s is not available", statusListType));
        };
        try {
            statusListRepository.save(statusList);
        } catch (DataIntegrityViolationException e) {
            throw new BadRequestException(String.format("Status List %s already exists", statusList.getUri()));
        }
    }

    public boolean canRevoke(StatusList statusList) {
        return switch (statusList.getType()) {
            case TOKEN_STATUS_LIST ->
                    (Integer) statusList.getConfig().get("bits") >= TokenStatsListBit.REVOKE.getBitNumber();
        };
    }

    public boolean canSuspend(StatusList statusList) {
        return switch (statusList.getType()) {
            case TOKEN_STATUS_LIST ->
                    (Integer) statusList.getConfig().get("bits") >= TokenStatsListBit.SUSPEND.getBitNumber();
        };
    }

    public void revoke(Set<CredentialOfferStatus> offerStatusSet) {
        Set<CredentialOfferStatus> revokableStatusSet = offerStatusSet.stream().filter(credentialOfferStatus -> canRevoke(credentialOfferStatus.getStatusList())).collect(Collectors.toSet());
        if (revokableStatusSet.isEmpty()) {
            throw new BadRequestException("No Status List which supports revocation found");
        }
        for (CredentialOfferStatus offerStatus : revokableStatusSet) {
            switch (offerStatus.getStatusList().getType()) {
                case TOKEN_STATUS_LIST ->
                        updateTokenStatusList(offerStatus, TokenStatsListBit.REVOKE.getBitNumber(), true);
            }
        }
    }

    public void suspend(Set<CredentialOfferStatus> offerStatusSet) {
        Set<CredentialOfferStatus> revokableStatusSet = offerStatusSet.stream().filter(credentialOfferStatus -> canSuspend(credentialOfferStatus.getStatusList())).collect(Collectors.toSet());
        if (revokableStatusSet.isEmpty()) {
            throw new BadRequestException("No Status List which supports suspension found");
        }
        for (CredentialOfferStatus offerStatus : revokableStatusSet) {
            switch (offerStatus.getStatusList().getType()) {
                case TOKEN_STATUS_LIST ->
                        updateTokenStatusList(offerStatus, TokenStatsListBit.SUSPEND.getBitNumber(), true);
            }
        }
    }

    public void unsuspend(Set<CredentialOfferStatus> offerStatusSet) {
        Set<CredentialOfferStatus> revokableStatusSet = offerStatusSet.stream().filter(credentialOfferStatus -> canSuspend(credentialOfferStatus.getStatusList())).collect(Collectors.toSet());
        if (revokableStatusSet.isEmpty()) {
            throw new BadRequestException("No Status List which supports suspension found");
        }
        for (CredentialOfferStatus offerStatus : revokableStatusSet) {
            switch (offerStatus.getStatusList().getType()) {
                case TOKEN_STATUS_LIST ->
                        updateTokenStatusList(offerStatus, TokenStatsListBit.SUSPEND.getBitNumber(), false);
            }
        }
    }

    /**
     * Updates the token status list by setting the given bit
     *
     * @param offerStatus
     * @param statusBit   the statusBit to be set
     * @param set         if the bit value should be set to 1
     */
    private void updateTokenStatusList(CredentialOfferStatus offerStatus, int statusBit, boolean set) {
        StatusList statusList = offerStatus.getStatusList();
        try {
            TokenStatusListToken token = TokenStatusListToken.loadTokenStatusListToken((Integer) statusList.getConfig().get("bits"), statusList.getStatusZipped());
            if (set) {
                token.setStatus(offerStatus.getIndex(), statusBit);
            } else {
                token.unsetStatus(offerStatus.getIndex(), statusBit);
            }
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
        TokenStatusListToken token = new TokenStatusListToken((Integer) config.get("bits"), statusListCreateDto.getMaxLength());

        // Build DB Entry
        StatusList statusList = StatusList.builder()
                .type(statusListCreateDto.getType())
                .config(statusListCreateDto.getConfig())
                .uri(statusListCreateDto.getUri())
                .statusZipped(token.getStatusListData())
                .lastUsedIndex(0)
                .maxLength(statusListCreateDto.getMaxLength())
                .build();

        updateRegistry(statusList, token);
        return statusList;
    }

    private void updateRegistry(StatusList statusListEntity, TokenStatusListToken token) {
        // Build JWT
        ECKey signingKey = statusListProperties.getStatusListKey().toECKey();

        SignedJWT statusListJWT = buildStatusListJWT(signingKey, statusListEntity, token);

        try {
            statusListJWT.sign(new ECDSASigner(signingKey));
        } catch (JOSEException e) {
            log.error("Failed to sign status list JWT with the provided key.", e);
            throw new ConfigurationException("Failed to sign status list JWT with the provided key.");
        }
        temporaryStatusListRestClientService.updateStatusList(statusListEntity.getUri(), statusListJWT.serialize());
    }

    private SignedJWT buildStatusListJWT(ECKey signingKey, StatusList statusListEntity, TokenStatusListToken token) {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(signingKey.getKeyID())
                .type(new JOSEObjectType("statuslist+jwt")).build();
        JWTClaimsSet claimSet = new JWTClaimsSet.Builder()
                .subject(statusListEntity.getUri())
                .issuer(applicationProperties.getIssuerId())
                .issueTime(new Date())
                .claim("status_list", token.getStatusListClaims())
                .build();
        SignedJWT statusListJWT = new SignedJWT(header, claimSet);
        return statusListJWT;
    }
}
