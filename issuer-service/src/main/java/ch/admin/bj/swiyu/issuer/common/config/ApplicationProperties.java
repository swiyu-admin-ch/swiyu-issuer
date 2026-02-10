/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.common.config;

import ch.admin.bj.swiyu.issuer.common.exception.ConfigurationException;
import com.nimbusds.jose.jwk.JWKSet;
import jakarta.annotation.Nullable;
import jakarta.annotation.PostConstruct;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import java.text.ParseException;
import java.time.Duration;
import java.util.List;
import java.util.Map;

@Slf4j
@Configuration
@Validated
@Data
@ConfigurationProperties(prefix = "application")
public class ApplicationProperties {

    @NotNull
    private String externalUrl;

    @NotEmpty
    private String deeplinkSchema;

    @NotNull
    private String issuerId;

    @NotNull
    private Long offerValidity;

    @NotNull
    private Integer deferredOfferValiditySeconds;

    @NotNull
    @Min(value = 5, message = "Minimal deferred offer interval must be at least 5 seconds")
    private Long minDeferredOfferIntervalSeconds;

    /**
     * List of DIDs of Attestation Providers deemed trustworthy for verifying the Key Attestation.
     */
    @NotNull
    private List<String> trustedAttestationProviders;

    @NotNull
    private String requestOfferVersion = "1.0";

    /**
     * If set to true the service expects all
     * writing message bodies to be encoded as JWT
     */
    @NotNull
    private boolean enableJwtAuthentication;

    /**
     * Flag to enable the storage of hashes of *each* VC signed by the generic issuer.
     * This is the JWS of the SD-JWT VC
     */
    @NotNull
    private boolean enableVcHashStorage;

    /**
     * If enableJWTAuthentication is set,
     * the JWTs will be checked against the public keys
     * stored in this json web key set.
     * Is expected to be a map with the key "keys"
     * <a href="https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.1">Example
     * how the JWKS is expected</a>
     */
    private String authenticationJwks;

    private JWKSet allowedKeySet;

    @NotNull
    private Map<String, String> templateReplacement;
    @Nullable
    private Map<String, String> vctMetadataFiles;
    @Nullable
    private Map<String, String> jsonSchemaMetadataFiles;
    @Nullable
    private Map<String, String> overlaysCaptureArchitectureMetadataFiles;

    @NotNull
    private long tokenTTL;

    /**
     * Flag Indicating if refresh tokens are used
     */
    @NotNull
    private boolean allowTokenRefresh;
    /**
     * Flag indicating if refresh tokens are changed after use
     */
    @NotNull
    private boolean allowRefreshTokenRotation;

    @NotNull
    private boolean renewalFlowAllowed;

    private String businessIssuerRenewalApiEndpoint;

    @NotNull
    private int acceptableProofTimeWindowSeconds;
    @NotNull
    private int nonceLifetimeSeconds;
    @NotNull
    private Duration encryptionKeyRotationInterval;
    private boolean encryptionEnforce;

    private boolean dpopEnforce;

    private boolean automaticStatusListSynchronizationDisabled;

    private String dataIntegrityJwks;
    private JWKSet dataIntegrityKeySet;
    private boolean dataIntegrityEnforced;
    private boolean signedMetadataEnabled;

    @PostConstruct
    public void init() {
        try {
            if (enableJwtAuthentication) {
                allowedKeySet = JWKSet.parse(authenticationJwks);
            }
            if (StringUtils.isNotBlank(dataIntegrityJwks)) {
                dataIntegrityKeySet = JWKSet.parse(dataIntegrityJwks);
            }
        } catch (ParseException e) {
            log.error("Provided Allow JWKSet can not be parsed! %s".formatted(authenticationJwks));
            throw new ConfigurationException(
                    "Provided Allow JWKSet can not be parsed! %s".formatted(authenticationJwks));
        }
    }

    public boolean isRenewalFlowEnabled() {
        return this.isDpopEnforce() && this.isRenewalFlowAllowed() && this.getBusinessIssuerRenewalApiEndpoint() != null;
    }
}