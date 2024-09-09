package ch.admin.bit.eid.issuer_management.services;

import ch.admin.bit.eid.issuer_management.config.ApplicationConfig;
import ch.admin.bit.eid.issuer_management.config.StatusListConfig;
import ch.admin.bit.eid.issuer_management.domain.StatusListRepository;
import ch.admin.bit.eid.issuer_management.domain.entities.StatusList;
import ch.admin.bit.eid.issuer_management.exceptions.BadRequestException;
import ch.admin.bit.eid.issuer_management.exceptions.ConfigurationException;
import ch.admin.bit.eid.issuer_management.exceptions.NotImplementedError;
import ch.admin.bit.eid.issuer_management.models.dto.StatusListCreateDto;
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
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Map;

@Slf4j
@Service
@AllArgsConstructor
public class StatusListService {

    private final ApplicationConfig applicationConfig;
    private final StatusListConfig statusListConfig;
    private final RestService restService;
    private final StatusListRepository statusListRepository;

    public void createStatusList(StatusListCreateDto statusListCreateDto) {
        var statusListType = statusListCreateDto.getType();
        StatusList statusList = switch (statusListType) {
            case ("TokenStatusList") -> initTokenStatusListToken(statusListCreateDto);
            default ->
                    throw new NotImplementedError(String.format("Statulist Type %s is not available", statusListType));
        };
        statusListRepository.save(statusList);
    }

    private StatusList initTokenStatusListToken(StatusListCreateDto statusListCreateDto) {
        Map<String, Object> config = statusListCreateDto.getConfig();
        if (config == null || config.get("bits") == null) {
            throw new BadRequestException("Must define 'bits' for TokenStatusList");
        }
        TokenStatusListToken token = new TokenStatusListToken((Integer) config.get("bits"), statusListCreateDto.getMaxLength());

        // Build DB Entry
        StatusList statusListEntity = StatusList.builder()
                .type(statusListCreateDto.getType())
                .config(statusListCreateDto.getConfig())
                .uri(statusListCreateDto.getUri())
                .statusZipped(token.getStatusListData())
                .lastUsedIndex(0)
                .maxLength(statusListCreateDto.getMaxLength())
                .build();

        // Build JWT
        ECKey signingKey = statusListConfig.getStatusListKey().toECKey();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(signingKey.getKeyID())
                .type(new JOSEObjectType("statuslist+jwt")).build();
        JWTClaimsSet claimSet = new JWTClaimsSet.Builder()
                .subject(statusListEntity.getUri())
                .issuer(applicationConfig.getIssuerId())
                .issueTime(new Date())
                .claim("status_list", token.getStatusListClaims())
                .build();

        SignedJWT statusListJWT = new SignedJWT(header, claimSet);
        try {
            statusListJWT.sign(new ECDSASigner(signingKey));
        } catch (JOSEException e) {
            log.error("Failed to sign status list JWT with the provided key.", e);
            throw new ConfigurationException("Failed to sign status list JWT with the provided key.");
        }
        restService.updateStatusList(statusListEntity.getUri(), statusListJWT.serialize());

        return statusListEntity;
    }
}
