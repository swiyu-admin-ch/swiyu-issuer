package ch.admin.bj.swiyu.issuer.service.statuslist;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.StatusListProperties;
import ch.admin.bj.swiyu.issuer.common.exception.ConfigurationException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusList;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.TokenStatusListToken;
import ch.admin.bj.swiyu.issuer.service.SignatureService;
import ch.admin.bj.swiyu.issuer.service.factory.strategy.KeyStrategyException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Date;

/**
 * Builds and signs the "statuslist+jwt" (draft status list token) for a {@link StatusList}.
 *
 * <p>Responsibilities:
 * <ul>
 *   <li>Build JOSE header + claims</li>
 *   <li>Apply issuer / verification-method overrides</li>
 *   <li>Sign with the configured key material</li>
 * </ul>
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class StatusListSigningService {

    private final ApplicationProperties applicationProperties;
    private final StatusListProperties statusListProperties;
    private final SignatureService signatureService;

    public SignedJWT buildSignedStatusListJwt(StatusList statusList, TokenStatusListToken token) {
        SignedJWT jwt = buildUnsignedStatusListJwt(statusList, token);
        var override = statusList.getConfigurationOverride();
        try {
            jwt.sign(signatureService.createSigner(statusListProperties, override.keyId(), override.keyPin()));
            return jwt;
        } catch (JOSEException | KeyStrategyException e) {
            log.error("Failed to sign status list JWT with the provided key.");
            throw new ConfigurationException("Failed to sign status list JWT with the provided key.", e);
        }
    }

    private SignedJWT buildUnsignedStatusListJwt(StatusList statusList, TokenStatusListToken token) {
        var override = statusList.getConfigurationOverride();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(override.verificationMethodOrDefault(statusListProperties.getVerificationMethod()))
                .type(new JOSEObjectType("statuslist+jwt"))
                .build();

        JWTClaimsSet claimSet = new JWTClaimsSet.Builder()
                .subject(statusList.getUri())
                .issuer(override.issuerDidOrDefault(applicationProperties.getIssuerId()))
                .issueTime(Date.from(Instant.now()))
                .claim("status_list", token.getStatusListClaims())
                .build();

        return new SignedJWT(header, claimSet);
    }
}
