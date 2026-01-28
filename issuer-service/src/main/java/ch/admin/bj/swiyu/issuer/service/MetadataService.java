package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.dto.oid4vci.OpenIdConfigurationDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.common.exception.ConfigurationException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.ConfigurationOverride;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.service.dpop.DemonstratingProofOfPossessionService;
import ch.admin.bj.swiyu.issuer.service.enc.JweService;
import ch.admin.bj.swiyu.jwssignatureservice.factory.strategy.KeyStrategyException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.time.DateUtils;
import org.springframework.aop.framework.Advised;
import org.springframework.aop.framework.AopProxyUtils;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.util.Date;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class MetadataService {

    private final OpenIdIssuerConfiguration openIdIssuerConfiguration;
    private final CredentialManagementService credentialManagementService;
    private final JwsSignatureFacade jwsSignatureFacade;
    private final JweService jweService;
    private final DemonstratingProofOfPossessionService demonstratingProofOfPossessionService;
    private final SdjwtProperties sdjwtProperties;
    private final ApplicationProperties applicationProperties;
    private final ObjectMapper objectMapper;

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
        IssuerMetadata issuerMetadata = jweService.issuerMetadataWithEncryptionOptions();
        // If we have a Spring Cache managed singleton, it would get serialized with the AOP wrapper when used directly
        return issuerMetadata instanceof Advised ? (IssuerMetadata) AopProxyUtils.getSingletonTarget(issuerMetadata) : issuerMetadata;
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
        try {
            return signMetadataJwt(objectMapper.writeValueAsString(getUnsignedIssuerMetadata()), override, tenantId);
        } catch (JsonProcessingException e) {
            throw new ConfigurationException("Unsigned Issuer Metadata could not be serialized as string", e);
        }
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
        return demonstratingProofOfPossessionService.addSigningAlgorithmsSupported(openIdIssuerConfiguration.getOpenIdConfiguration());
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

        try {
            return signMetadataJwt(objectMapper.writeValueAsString(getUnsignedOpenIdConfiguration()), override, tenantId);
        } catch (JsonProcessingException e) {
            throw new ConfigurationException("Unsigned OAuth 2.0 configuration could not be serialized as string", e);
        }
    }

    private String signMetadataJwt(String metaDataJson, ConfigurationOverride override, UUID tenantId) {
        try {
            JWSSigner signer;

            signer = jwsSignatureFacade.createSigner(sdjwtProperties, override.keyId(), override.keyPin());


            /*
             * alg: Must be ES256
             * typ: Must be openidvci-issuer-metadata+jwt
             * kid: Must be the time when the JWT was issued
             */
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .keyID(override.verificationMethodOrDefault(sdjwtProperties.getVerificationMethod()))
                    .type(new JOSEObjectType("openidvci-issuer-metadata+jwt"))
                    .build();

            JWTClaimsSet claimsSet = prepareJWTClaimsSet(override, metaDataJson);

            SignedJWT jwt = new SignedJWT(header, claimsSet);
            jwt.sign(signer);
            return jwt.serialize();
        } catch (JOSEException e) {
            log.error("Unable to sign metadata for tenant %s".formatted(tenantId), e);
            throw new ConfigurationException("Unable to sign metadata for tenant %s", e);
        } catch (KeyStrategyException e) {
            log.error("Failed to signed metadata JWT with the provided key %s".formatted(override.keyId()));
            throw new ConfigurationException("Failed to signed metadata JWT with the provided key", e);
        } catch (ParseException e) {
            log.error("Unable to parse the metadata to a JSON");
            throw new ConfigurationException("Unable to parse the metadata to a JSON", e);
        }


    }

    private JWTClaimsSet prepareJWTClaimsSet(ConfigurationOverride override,
                                             String metaDataJson) throws ParseException {

        /*
         * sub: Must be the external URL
         * iat: Must be the time when the JWT was issued
         * exp: Optional the time when the Metadata are expiring -> default 24h
         * iss: Optional denoting the party attesting to the claims in the signed metadata
         */
        JWTClaimsSet metaData = JWTClaimsSet.parse(metaDataJson);

        // Override JWT claims,
        JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder(metaData)
                .subject(applicationProperties.getExternalUrl())
                .issueTime(new Date())
                .issuer(override.issuerDidOrDefault(applicationProperties.getIssuerId()))
                .expirationTime(DateUtils.addHours(new Date(), 24));


        return claimsSetBuilder.build();
    }
}