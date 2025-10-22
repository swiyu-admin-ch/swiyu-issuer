package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.OpenIdIssuerConfiguration;
import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.common.exception.ConfigurationException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.ConfigurationOverride;
import ch.admin.bj.swiyu.issuer.service.factory.strategy.KeyStrategyException;
import com.nimbusds.jose.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.time.DateUtils;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

@Service
@AllArgsConstructor
@Slf4j
public class MetadataService {

    private final OpenIdIssuerConfiguration openIdIssuerConfiguration;
    private final CredentialManagementService credentialManagementService;
    private final SignatureService signatureService;
    private final SdjwtProperties sdjwtProperties;

    public Map<String, Object> getUnsignedIssuerMetadata() {
        try {
            return openIdIssuerConfiguration.getIssuerMetadata();
        } catch (IOException e) {
            log.error("Failed to read the provided metadata", e);
            throw new ConfigurationException("Failed to read the provided metadata");
        }
    }

    public String getSignedIssuerMetadata(UUID tenantId) {
        var override = credentialManagementService.getConfigurationOverrideByTenantId(tenantId);

        return signMetadataJwt(getUnsignedIssuerMetadata(), override, tenantId);
    }

    public Map<String, Object> getUnsignedOpenIdConfiguration() {
        try {
            return openIdIssuerConfiguration.getOpenIdConfiguration();
        } catch (IOException e) {
            log.error("Failed to read the provided metadata", e);
            throw new ConfigurationException("Failed to read the provided metadata");
        }
    }

    public String getSignedOpenIdConfiguration(UUID tenantId) {
        var override = credentialManagementService.getConfigurationOverrideByTenantId(tenantId);

        return signMetadataJwt(getUnsignedOpenIdConfiguration(), override, tenantId);
    }

    private String signMetadataJwt(Map<String, Object> metaData, ConfigurationOverride override, UUID tenantId) {

        JWSSigner signer = null;
        try {
            signer = signatureService.createSigner(sdjwtProperties, override.keyId(), override.keyPin());
        } catch (KeyStrategyException e) {
            log.error("Failed to signed metadata JWT with the provided key", e);
            throw new ConfigurationException("Failed to signed metadata JWT with the provided key");
        }

        /*
         * alg: Must be ES256
         * typ: Must be openidvci-issuer-metadata+jwt
         * kid: Must be the time when the JWT was issued
         */
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(override.keyId())
                .type(new JOSEObjectType("openidvci-issuer-metadata+jwt"))
                .build();

        /*
         * sub: Must match the issuer did
         * iat: Must be the time when the JWT was issued
         * exp: Optional the time when the Metadata are expiring -> default 24h
         */
        JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
                .subject(override.issuerDid())
                .issueTime(new Date())
                .expirationTime(DateUtils.addHours(new Date(), 24));

        // add all metadata claims to JWT Claim Set
        for (Map.Entry<String, Object> entry : metaData.entrySet()) {
            String key = entry.getKey();

            // ignore reserved claims
            if ("sub".equals(key) || "iat".equals(key) || "exp".equals(key) || "iss".equals(key)) {
                continue;
            }
            claimsSetBuilder.claim(key, entry.getValue());
        }

        SignedJWT jwt = new SignedJWT(header, claimsSetBuilder.build());

        try {
            jwt.sign(signer);
        } catch (JOSEException e) {
            log.error("Unable to sign metadata for tenant %s".formatted(tenantId), e);
            throw new ConfigurationException("Unable to sign metadata for tenant %s");
        }

        return jwt.serialize();
    }
}