/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

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
    private CredentialStatusType credentialStatus;

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
    private Map<String, Object> credentialMetadata;

    /**
     * Value used for the oid bearer token given to the holder
     */
    @NotNull
    private UUID accessToken;

    /**
     * Value used for the deferred flow to get the credential
     */
    private UUID transactionId;

    /**
     * Value used for the store the public key from the holder received in the deferred flow
     */
    @Column(name = "holder_jwk")
    private String holderJWK;

    /**
     * Value used to store client agent infos for the deferred flow
     */
    @JdbcTypeCode(SqlTypes.JSON)
    private ClientAgentInfo clientAgentInfo;

    /**
     * Expiration in unix epoch (since 1.1.1970) timestamp in seconds
     */
    private long tokenExpirationTimestamp;

    /**
     * Value used in the holder binding process to prevent replay attacks
     */
    private UUID nonce;

    /**
     * Value used to get the token for grant-type:pre-authorized_code
     */
    private UUID preAuthorizedCode;

    private long offerExpirationTimestamp;

    private Instant credentialValidFrom;

    private Instant credentialValidUntil;

    /**
     * This claim is contained in the response if the Credential Issuer was unable to immediately issue the Credential.
     * Is removed after the Credential has been obtained by the Wallet
     */
    @JdbcTypeCode(SqlTypes.JSON)
    private CredentialRequestClass credentialRequest;

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

    public void removeOfferData() {
        this.offerData = null;
    }

    public void changeStatus(CredentialStatusType credentialStatus) {
        this.credentialStatus = credentialStatus;
    }

    public boolean hasExpirationTimeStampPassed() {
        return Instant.now().isAfter(Instant.ofEpochSecond(this.offerExpirationTimestamp));
    }

    public void expire() {
        this.changeStatus(CredentialStatusType.EXPIRED);
        this.removeOfferData();
    }

    public void cancel() {
        this.changeStatus(CredentialStatusType.CANCELLED);
        this.removeOfferData();
    }

    public void markAsIssued() {
        this.invalidateOfferData();
        this.credentialStatus = CredentialStatusType.ISSUED;
        log.info("Credential issued for offer {}. Management-ID is {}. ",
                this.metadataCredentialSupportedId, this.id);
    }

    public void markAsInProgress() {
        this.credentialStatus = CredentialStatusType.IN_PROGRESS;
        if (this.accessToken == null) {
            this.accessToken = UUID.randomUUID();
        }
    }

    public void setTokenIssuanceTimestamp(long tokenTTL) {
        this.tokenExpirationTimestamp = Instant.now().plusSeconds(tokenTTL).getEpochSecond();
    }

    public void markAsExpired() {
        this.credentialStatus = CredentialStatusType.EXPIRED;
        this.invalidateOfferData();
        log.info("Credential expired for offer {}. Management-ID is {}.", this.metadataCredentialSupportedId, this.id);
    }

    public void markAsDeferred(UUID transactionId,
                               CredentialRequestClass credentialRequest,
                               String holderPublicKey,
                               ClientAgentInfo clientAgentInfo) {
        this.credentialStatus = CredentialStatusType.DEFERRED;
        this.credentialRequest = credentialRequest;
        this.transactionId = transactionId;
        this.holderJWK = holderPublicKey;
        this.clientAgentInfo = clientAgentInfo;
        log.info("Deferred credential response for offer {}. Management-ID is {} and status is {}. ",
                this.metadataCredentialSupportedId, this.id, this.credentialStatus);
    }

    public void markAsReadyForIssuance(Map<String, Object> offerData) {
        this.credentialStatus = CredentialStatusType.READY;
        this.setOfferData(offerData);
        log.info("Deferred Credential ready for issuance for offer {}. Management-ID is {} and status is {}. ",
                this.metadataCredentialSupportedId, this.id, this.credentialStatus);
    }

    public boolean hasTokenExpirationPassed() {
        return Instant.now().isAfter(Instant.ofEpochSecond(this.tokenExpirationTimestamp));
    }

    public boolean isDeferred() {
        if (credentialMetadata == null) {
            return false;
        }
        return nonNull(credentialMetadata.get("deferred")) && (boolean) credentialMetadata.get("deferred");
    }

    private void invalidateOfferData() {
        this.offerData = null;
        this.transactionId = null;
        this.credentialRequest = null;
        this.holderJWK = null;
        this.clientAgentInfo = null;
    }
}