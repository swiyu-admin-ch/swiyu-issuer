package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.api.oid4vci.OpenIdConfigurationDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.common.exception.ConfigurationException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.ConfigurationOverride;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.service.factory.strategy.KeyStrategyException;
import com.nimbusds.jose.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.time.DateUtils;
import org.springframework.stereotype.Service;

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
    private final ApplicationProperties applicationProperties;

    /**
     * Returns the issuer metadata without signing.
     *
     * <p>Retrieves the current {@link IssuerMetadata} from the configured
     * {@code OpenIdIssuerConfiguration} and returns it in its original,
     * unsigned form.
     *
     * @return the unsigned {@link IssuerMetadata} for this issuer
     */
    public IssuerMetadata getUnsignedIssuerMetadata() {
        return openIdIssuerConfiguration.getIssuerMetadata();
    }

    /**
     * Returns a signed issuer metadata JWT for the specified tenant.
     *
     * <p>Retrieves the tenant-specific {@code ConfigurationOverride} from
     * {@code CredentialManagementService} and signs the issuer metadata map using the
     * configured signature service.
     *
     * @param tenantId the tenant identifier for which to produce the signed issuer metadata
     * @return a serialized JWT containing the signed issuer metadata
     * @throws ConfigurationException if signing the metadata fails or the key strategy cannot be created
     */
    public String getSignedIssuerMetadata(UUID tenantId) {
        var override = credentialManagementService.getConfigurationOverrideByTenantId(tenantId);

        return signMetadataJwt(openIdIssuerConfiguration.getIssuerMetadataMap(), override, tenantId);
    }

    /**
     * Returns the OpenID Provider Configuration as a DTO without signing.
     *
     * <p>The configuration is retrieved from {@code openIdIssuerConfiguration} and is returned
     * in its original, unsigned form.
     *
     * @return the unsigned {@link OpenIdConfigurationDto} for this issuer
     */
    public OpenIdConfigurationDto getUnsignedOpenIdConfiguration() {
        return openIdIssuerConfiguration.getOpenIdConfiguration();
    }

    /**
     * Returns a signed OpenID configuration JWT for the given tenant.
     *
     * <p>Retrieves the tenant-specific {@code ConfigurationOverride} from
     * {@code CredentialManagementService} and signs the OpenID configuration map
     * using the configured signature service.
     *
     * @param tenantId the tenant identifier for which to sign the OpenID configuration
     * @return a serialized JWT containing the signed OpenID configuration
     */
    public String getSignedOpenIdConfiguration(UUID tenantId) {
        var override = credentialManagementService.getConfigurationOverrideByTenantId(tenantId);

        return signMetadataJwt(openIdIssuerConfiguration.getOpenIdConfigurationMap(), override, tenantId);
    }

    private String signMetadataJwt(Map<String, Object> metaData, ConfigurationOverride override, UUID tenantId) {

        JWSSigner signer;
        try {
            signer = signatureService.createSigner(sdjwtProperties, override.keyId(), override.keyPin());
        } catch (KeyStrategyException e) {
            log.error("Failed to signed metadata JWT with the provided key %s".formatted(override.keyId()));
            throw new ConfigurationException("Failed to signed metadata JWT with the provided key", e);
        }

        /*
         * alg: Must be ES256
         * typ: Must be openidvci-issuer-metadata+jwt
         * kid: Must be the time when the JWT was issued
         */
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .keyID(override.verificationMethodOrDefault(sdjwtProperties.getVerificationMethod()))
                .type(new JOSEObjectType("openidvci-issuer-metadata+jwt"))
                .build();

        JWTClaimsSet claimsSet = prepareJWTClaimsSet(override, metaData);

        SignedJWT jwt = new SignedJWT(header, claimsSet);

        try {
            jwt.sign(signer);
        } catch (JOSEException e) {
            log.error("Unable to sign metadata for tenant %s".formatted(tenantId), e);
            throw new ConfigurationException("Unable to sign metadata for tenant %s", e);
        }

        return jwt.serialize();
    }

    private JWTClaimsSet prepareJWTClaimsSet(ConfigurationOverride override,
                                             Map<String, Object> metaData) {

        /*
         * sub: Must match the issuer did
         * iat: Must be the time when the JWT was issued
         * exp: Optional the time when the Metadata are expiring -> default 24h
         */
        JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder()
                .subject(override.issuerDidOrDefault(applicationProperties.getIssuerId()))
                .issueTime(new Date())
                .expirationTime(DateUtils.addHours(new Date(), 24));

        // add all metadata claims to JWT Claim Set
        metaData.forEach((key, value) -> {
            if (!isReservedClaim(key)) {
                claimsSetBuilder.claim(key, value);
            }
        });

        return claimsSetBuilder.build();
    }

    private boolean isReservedClaim(String claim) {
        return "sub".equals(claim) || "iat".equals(claim) || "exp".equals(claim) || "iss".equals(claim);
    }
}