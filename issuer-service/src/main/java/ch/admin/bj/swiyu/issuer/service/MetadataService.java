package ch.admin.bj.swiyu.issuer.service;

import java.text.ParseException;
import java.util.Date;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.apache.commons.lang3.time.DateUtils;
import org.springframework.aop.framework.Advised;
import org.springframework.aop.framework.AopProxyUtils;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import ch.admin.bj.swiyu.dpop.DpopConstants;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.common.exception.ConfigurationException;
import ch.admin.bj.swiyu.issuer.common.profile.SwissProfileVersions;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.ConfigurationOverride;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialConfiguration;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.OAuthAuthorizationServerMetadataDto;
import ch.admin.bj.swiyu.issuer.service.credential.OpenIdIssuerConfiguration;
import ch.admin.bj.swiyu.issuer.service.enc.JweService;
import ch.admin.bj.swiyu.issuer.service.management.CredentialManagementService;
import ch.admin.bj.swiyu.issuer.service.trustregistry.TrustStatementInjectionService;
import ch.admin.bj.swiyu.jwssignatureservice.factory.strategy.KeyStrategyException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class MetadataService {

    private final OpenIdIssuerConfiguration openIdIssuerConfiguration;
    private final CredentialManagementService credentialManagementService;
    private final JwsSignatureFacade jwsSignatureFacade;
    private final JweService jweService;
    private final SdjwtProperties sdjwtProperties;
    private final ApplicationProperties applicationProperties;
    private final ObjectMapper objectMapper;

    /**
     * Optional service for injecting Trust Protocol 2.0 trust statements into issuer metadata.
     * Present only when {@code swiyu.trust-registry.api-url} is configured.
     */
    private final Optional<TrustStatementInjectionService> trustStatementInjectionService;

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
        return unwrapProxy(issuerMetadata);
    }

    /**
     * Returns the unsigned issuer metadata for the default issuer, with Trust Protocol 2.0 trust statements injected.
     * <p>
     * This method creates a fresh, thread-local copy of the base issuer metadata and injects the current
     * trust statements (idTS, piaTS) for the default issuer DID, if the TrustStatementInjectionService is present.
     * <p>
     *
     * @return the unsigned {@link IssuerMetadata} for the default issuer, including injected trust statements if available
     */
    public IssuerMetadata getUnsignedIssuerMetadataWithTS() {
        IssuerMetadata base = unwrapProxy(jweService.issuerMetadataWithEncryptionOptions());
        IssuerMetadata result = base.toBuilder().build();
        trustStatementInjectionService.ifPresent(s ->
                s.injectTrustStatements(result, applicationProperties.getIssuerId())
        );
        return result;
    }

    /**
     * Returns an instance of the issuer metadata without signing where the credential_issuer path has been extended by the tenantId.
     * Note: The credential issuer identifier needs to match exactly the one provided in the credential offer. <br>
     * Append the tenant ID to the credential identifier; for example <br>
     * https://www.example.com/oid4vci will become <br>
     * https://www.example.com/oid4vci/00000000-0000-0000-0000-000000000000<br>
     *
     * @param tenantId the tenant identifier for which to produce the unsigned issuer metadata
     * @return the unsigned {@link IssuerMetadata} instance for this issuer tenant
     */
    public IssuerMetadata getUnsignedIssuerMetadata(UUID tenantId) {
        var baseUnsignedMetadata = getUnsignedIssuerMetadata();
        return buildTenantMetadata(baseUnsignedMetadata, tenantId);
    }

    /**
     * Returns an instance of the issuer metadata without signing where the credential_issuer path has been extended by the tenantId.
     * Note: The credential issuer identifier needs to match exactly the one provided in the credential offer. <br>
     * Append the tenant ID to the credential identifier; for example <br>
     * https://www.example.com/oid4vci will become <br>
     * https://www.example.com/oid4vci/00000000-0000-0000-0000-000000000000<br>
     *
     * @param tenantId the tenant identifier for which to produce the unsigned issuer metadata
     * @return the unsigned {@link IssuerMetadata} instance for this issuer tenant
     */
    public IssuerMetadata getUnsignedIssuerMetadataWithTS(UUID tenantId) {
        var override = credentialManagementService.getConfigurationOverrideByTenantId(tenantId);
        String issuerDid = override.issuerDidOrDefault(applicationProperties.getIssuerId());

        IssuerMetadata base = unwrapProxy(jweService.issuerMetadataWithEncryptionOptions());
        IssuerMetadata result = buildTenantMetadata(base, tenantId);

        trustStatementInjectionService.ifPresent(s -> s.injectTrustStatements(result, issuerDid));
        return result;
    }


    /**
     * Updates the supported credential configurations by merging metadata from the provided
     * credential offer with the existing base metadata.
     * If the credential offer contains metadata and a valid configuration ID, the corresponding
     * credential configuration is updated with new metadata URI and integrity values.
     * The method then returns the updated map of supported credential configurations.
     *
     * @param issuerMetadata the issuer metadata to be updated
     * @param tenantId the tenant identifier for which to produce the updated credential configuration
     * @return the map of updated supported {@link CredentialConfiguration}
     */
    private Map<String, CredentialConfiguration> getUpdatedSupportedCredentialConfigurations(
            IssuerMetadata issuerMetadata, UUID tenantId) {
        var credentialOffer = credentialManagementService.getCredentialOfferByTenantId(tenantId);
        var supportedCredentialConfigurations = issuerMetadata.getCredentialConfigurationSupported();
        if (credentialOffer == null) {
            return supportedCredentialConfigurations;
        }
        var credentialMetadata = credentialOffer.getCredentialMetadata();
        if (credentialMetadata != null) {
            var configurationId = credentialOffer.getMetadataCredentialSupportedId().getFirst();
            var baseCredentialConfiguration = issuerMetadata.getCredentialConfigurationById(configurationId);
            supportedCredentialConfigurations.put(configurationId, baseCredentialConfiguration.toBuilder()
                .vctMetadataUri(credentialMetadata.getVctMetadataUriOrDefault(baseCredentialConfiguration.getVctMetadataUri()))
                .vctMetadataUriIntegrity(credentialMetadata.getVctMetadataUriIntegrityOrDefault(baseCredentialConfiguration.getVctMetadataUriIntegrity()))
                .build());
        }
        return supportedCredentialConfigurations;
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
            return signMetadataJwt(objectMapper.writeValueAsString(getUnsignedIssuerMetadata(tenantId)), override, tenantId);
        } catch (JsonProcessingException e) {
            throw new ConfigurationException("Unsigned Issuer Metadata could not be serialized as string", e);
        }
    }

    /**
     * Returns a signed issuer metadata JWT including Trust Protocol 2.0 trust statements for the specified tenant.
     *
     * <p>The tenant's {@code ConfigurationOverride} is resolved once and reused for both
     * building the metadata (including TS injection) and signing the JWT.</p>
     *
     * @param tenantId the tenant identifier for which to produce the signed issuer metadata
     * @return a serialized JWT containing the signed issuer metadata with trust statements
     * @throws ConfigurationException if signing the metadata fails or the key strategy cannot be created
     */
    public String getSignedIssuerMetadataWithTS(UUID tenantId) {
        var override = credentialManagementService.getConfigurationOverrideByTenantId(tenantId);
        try {
            return signMetadataJwt(objectMapper.writeValueAsString(getUnsignedIssuerMetadataWithTS(tenantId)), override, tenantId);
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
     * @return the unsigned {@link OAuthAuthorizationServerMetadataDto} for this issuer
     */
    public OAuthAuthorizationServerMetadataDto getUnsignedOAuthAuthorizationServerMetadata() {
        return addSigningAlgorithmsSupportedAndSwissprofileVersion(
                    openIdIssuerConfiguration.getOpenIdConfiguration()
                );
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
    public String getSignedOAuthAuthorizationServerMetadata(UUID tenantId) {
        var override = credentialManagementService.getConfigurationOverrideByTenantId(tenantId);

        try {
            return signMetadataJwt(objectMapper.writeValueAsString(getUnsignedOAuthAuthorizationServerMetadata(tenantId)), override, tenantId);
        } catch (JsonProcessingException e) {
            throw new ConfigurationException("Unsigned OAuth 2.0 configuration could not be serialized as string", e);
        }
    }

        /**
     * Returns the Authorization Server Metadata as a DTO without signing.
     *
     * <p>The configuration is retrieved from {@code OAuthAuthorizationServerMetadata} and is returned
     * in its original, unsigned form.
     *
     * @return the unsigned {@link OAuthAuthorizationServerMetadataDto} for this issuer
     */
    public OAuthAuthorizationServerMetadataDto getUnsignedOAuthAuthorizationServerMetadata(UUID tenantId) {
        return getUnsignedOAuthAuthorizationServerMetadata().toBuilder()
                .issuer(createTenantCredentialIssuerIdentifier(tenantId))
                .build();
    }

    /**
     * Calculates the Credential Issuer Identifier for a specific tenant.
     * <br>
     * Credential Issuer Identifiers contain the full path of a tenant.
     *
     * @param tenantId the tenant identifier for which to create a credential issuer identifier
     * @return credential Issuer Identifier (credential_issuer) for the tenant
     */
    private String createTenantCredentialIssuerIdentifier(UUID tenantId) {
        String commonCredentialIssuerIdentifier = jweService.issuerMetadataWithEncryptionOptions().getCredentialIssuer();
        return String.format("%s/%s", commonCredentialIssuerIdentifier, tenantId);
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
                    .customParam(SwissProfileVersions.PROFILE_VERSION_PARAM, SwissProfileVersions.ISSUANCE_PROFILE_VERSION)
                    .build();

            JWTClaimsSet claimsSet = prepareJWTClaimsSet(override, metaDataJson, createTenantCredentialIssuerIdentifier(tenantId));

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
                                             String metaDataJson, String subject) throws ParseException {

        /*
         * sub: Must be the external URL
         * iat: Must be the time when the JWT was issued
         * exp: Optional the time when the Metadata are expiring -> default 24h
         * iss: Optional denoting the party attesting to the claims in the signed metadata
         */
        JWTClaimsSet metaData = JWTClaimsSet.parse(metaDataJson);

        // Override JWT claims,
        JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder(metaData)
                .subject(subject)
                .issueTime(new Date())
                .issuer(override.issuerDidOrDefault(applicationProperties.getIssuerId()))
                .expirationTime(DateUtils.addHours(new Date(), 24));


        return claimsSetBuilder.build();
    }

    /**
     * Extend OpenIdConfiguration with the signing algorithms supported for DPoP.
     *
     * @param openIdConfiguration The configuration to be extended
     * @return the openidConfiguration with added dpop_signing_alg_values_supported
     */
    public OAuthAuthorizationServerMetadataDto addSigningAlgorithmsSupportedAndSwissprofileVersion(OAuthAuthorizationServerMetadataDto openIdConfiguration) {
        var builder = openIdConfiguration.toBuilder();
        builder.dpop_signing_alg_values_supported(DpopConstants.SUPPORTED_ALGORITHMS)
                .profile_version(SwissProfileVersions.ISSUANCE_PROFILE_VERSION)
                .preauthorized_grant_anonymous_access_supported(true);
    
        return builder.build();
    }

    /**
     * Unwraps an AOP proxy to obtain the underlying {@link IssuerMetadata} target.
     * Required when the metadata is a Spring Cache managed singleton.
     */
    private IssuerMetadata unwrapProxy(IssuerMetadata issuerMetadata) {
        return issuerMetadata instanceof Advised
                ? (IssuerMetadata) AopProxyUtils.getSingletonTarget(issuerMetadata)
                : issuerMetadata;
    }

    /**
     * Builds tenant-scoped issuer metadata by extending the base metadata with the tenant ID
     * and merging any per-offer credential configuration overrides.
     *
     * @param base     the resolved base issuer metadata
     * @param tenantId the tenant identifier
     * @return the tenant-scoped {@link IssuerMetadata}
     */
    private IssuerMetadata buildTenantMetadata(IssuerMetadata base, UUID tenantId) {
        var supportedCredentialConfigurations = getUpdatedSupportedCredentialConfigurations(base, tenantId);
        return base.toBuilder()
                .credentialIssuer(createTenantCredentialIssuerIdentifier(tenantId))
                .credentialConfigurationSupported(supportedCredentialConfigurations)
                .build();
    }
}

