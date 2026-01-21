/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.domain.AuditMetadata;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.*;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.*;

import static java.util.Objects.nonNull;

/**
 * Representation of a single offer and the vc which was created using that
 * offer.
 * This object serves as a link between the business issuer and the issued
 * verifiable credential (vc).
 */
@Entity
@Getter
@Setter
@Builder
@Slf4j
@NoArgsConstructor(access = AccessLevel.PROTECTED) // JPA
@AllArgsConstructor // test data
@EntityListeners(AuditingEntityListener.class)
@Table(name = "credential_offer")
public class CredentialOffer {

    @Embedded
    @Valid
    private final AuditMetadata auditMetadata = new AuditMetadata();

    @Id
    @Builder.Default
    private UUID id = UUID.randomUUID(); // Generate the ID manually

    /**
     * internal Credential status, includes status before issuing the VC,
     * which can not be covered by the status list
     */
    @Enumerated(EnumType.STRING)
    @Setter(AccessLevel.NONE) //
    private CredentialOfferStatusType credentialStatus;

    /**
     * ID String referencing the entry in the issuer metadata of the signer
     */
    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> metadataCredentialSupportedId;

    /**
     * the Credential Subject Data. Has the shape for unprotected data
     *
     * <pre>
     * <code>
     * {
     *     "data": vc data json
     * }
     * </code>
     * </pre>
     * <p>
     * For data integrity protected data uses the shape
     *
     * <pre>
     * <code>
     * {
     *     "data": jwt encoded vc data string,
     *     "data_integrity": "jwt"
     * }
     * </code>
     * </pre>
     */
    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> offerData;

    /**
     * VC Type specific metadata which is dynamically provisioned.
     * For example vct#integrity for SD-JWT VC.
     */
    @JdbcTypeCode(SqlTypes.JSON)
    private CredentialOfferMetadata credentialMetadata;

    /**
     * Value used for the deferred flow to get the credential
     */
    private UUID transactionId;

    /**
     * TenantId from the metadata where the credential offer was created
     * Used to sign the metadata with the correct key
     */
    private UUID metadataTenantId;

    /**
     * Value used for the store the public key from the holder received in the deferred flow
     */
    @Column(name = "holder_jwks")
    private List<String> holderJWKs;

    /**
     * Value used for the store the public key from the holder received in the deferred flow
     */
    @Column(name = "key_attestations")
    private List<String> keyAttestations;

    /**
     * Value used to store client agent infos for the deferred flow
     */
    @JdbcTypeCode(SqlTypes.JSON)
    private ClientAgentInfo clientAgentInfo;

    /**
     * Value used in the holder binding process to prevent replay attacks
     */
    @Deprecated(since = "OID4VCI 1.0")
    private UUID nonce;

    /**
     * Value used to get the token for grant-type:pre-authorized_code
     */
    private UUID preAuthorizedCode;

    /**
     * Timestamp after which the credential offer or the deferred credential offer will be regarded as expired.
     */
    private Long offerExpirationTimestamp;

    private Integer deferredOfferValiditySeconds;

    private Instant credentialValidFrom;

    private Instant credentialValidUntil;

    /**
     * This claim is contained in the response if the Credential Issuer was unable to immediately issue the Credential.
     * Is removed after the Credential has been obtained by the Wallet
     */
    @JdbcTypeCode(SqlTypes.JSON)
    private CredentialRequestClass credentialRequest;

    /**
     * Overrides for a single status list's configuration normally injected via application properties
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "configuration_override", columnDefinition = "jsonb")
    private ConfigurationOverride configurationOverride;

    /**
     * Reference to Credential Management entry
     */
    @ManyToOne
    @JoinColumn(name = "credential_management_id", nullable = false)
    private CredentialManagement credentialManagement;

    /**
     * Read the offer data depending on input type and add it to offer
     *
     * @param offerData can be string or map -> other will throw exception
     * @return offerdata map
     */
    public static Map<String, Object> readOfferData(Object offerData) {
        if (offerData instanceof String string) {
            return readOfferDataString(string);
        } else if (offerData instanceof Map<?, ?>) {
            return readOfferDataMap((Map<?, ?>) offerData);
        } else {
            throw new BadRequestException(String.format("Unsupported OfferData %s", offerData));
        }
    }

    private static Map<String, Object> readOfferDataString(String offerData) {
        var metadata = new LinkedHashMap<String, Object>();

        metadata.put("data", offerData);
        metadata.put("data_integrity", "jwt");

        return metadata;
    }

    private static Map<String, Object> readOfferDataMap(Map<?, ?> offerData) {
        var metadata = new LinkedHashMap<String, Object>();

        var mapper = new ObjectMapper();
        try {
            metadata.put("data", mapper.writeValueAsString(offerData));
            return metadata;
        } catch (JsonProcessingException e) {
            throw new BadRequestException(String.format("Unsupported OfferData %s", offerData));
        }
    }

    public boolean hasExpirationTimeStampPassed() {
        return this.offerExpirationTimestamp != null &&
                Instant.now().isAfter(Instant.ofEpochSecond(this.offerExpirationTimestamp));
    }

    public void initializeDeferredState(UUID transactionId,
                                        CredentialRequestClass credentialRequest,
                                        List<String> holderPublicKey,
                                        List<String> keyAttestationJWTs,
                                        ClientAgentInfo clientAgentInfo,
                                        ApplicationProperties applicationProperties) {

        var expiration = Instant.now().plusSeconds(nonNull(deferredOfferValiditySeconds) && deferredOfferValiditySeconds > 0
                ? deferredOfferValiditySeconds
                : applicationProperties.getDeferredOfferValiditySeconds());

        this.credentialRequest = credentialRequest;
        this.transactionId = transactionId;
        this.holderJWKs = !holderPublicKey.isEmpty() ? holderPublicKey : null;
        this.clientAgentInfo = clientAgentInfo;
        this.keyAttestations = keyAttestationJWTs;

        // update expiration for deferred flow
        this.offerExpirationTimestamp = expiration.getEpochSecond();

        log.info("Deferred credential response for offer {}. Management ID is {}, offer ID is {} and status is {}. ",
                this.getMetadataCredentialSupportedId(), this.getCredentialManagement().getId(), this.getId(), this.getCredentialStatus());
    }

    public boolean isDeferredOffer() {
        return credentialMetadata != null && Boolean.TRUE.equals(credentialMetadata.deferred());
    }

    public boolean isProcessableOffer() {
        return this.credentialStatus.isProcessable();
    }

    public boolean isTerminatedOffer() {
        return this.credentialStatus.isTerminalState();
    }

    @NotNull
    public ConfigurationOverride getConfigurationOverride() {
        return Objects.requireNonNullElseGet(this.configurationOverride, () -> new ConfigurationOverride(null, null, null, null));
    }

    public void invalidateOfferData() {
        this.offerData = null;
        this.transactionId = null;
        this.credentialRequest = null;
        this.holderJWKs = null;
        this.clientAgentInfo = null;
        this.keyAttestations = null;
        this.offerExpirationTimestamp = 0L;
    }

    /**
     * Sets the status of this credential offer entity.
     * <p>
     * <b>Intended for use by {@link CredentialStateMachine} only.</b>
     * Do not use outside the state machine context to ensure correct state transitions.
     *
     * @param credentialOfferStatus the new status to set
     */
    void setCredentialOfferStatus(CredentialOfferStatusType credentialOfferStatus) {
        this.credentialStatus = credentialOfferStatus;
    }

    /**
     * Sets the status of this credential offer entity.
     * <p>
     * <b>Intended for test usage only.</b>
     * Do not use in production code.
     * Always use the state machine to change states!
     *
     * @param credentialOfferStatus the new status to set
     */
    public void setCredentialOfferStatusJustForTestUsage(CredentialOfferStatusType credentialOfferStatus) {
        this.credentialStatus = credentialOfferStatus;
    }

}