/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.domain.credentialoffer;

import ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.credentialrequest.CredentialRequest;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import static java.util.Objects.nonNull;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.AuditMetadata;
import jakarta.validation.Valid;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Entity
@Table(name = "credential_offer")
@Getter
@Setter
@Slf4j
@NoArgsConstructor(access = AccessLevel.PROTECTED) // JPA
@AllArgsConstructor // test data
@EntityListeners(AuditingEntityListener.class)
public class CredentialOffer {

    @Embedded
    @Valid
    private final AuditMetadata auditMetadata = new AuditMetadata();

    @Id
    private UUID id;

    /**
     * internal Credential status, includes status before issuing the VC,
     * which can not be covered by the status list
     */
    @Enumerated(EnumType.STRING)
    private CredentialStatus credentialStatus;

    /**
     * ID String referencing the entry in the issuer metadata of the signer
     */
    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> metadataCredentialSupportedId;

    /**
     * Offer data comes wrapped with some metadata
     * <p>
     * for raw offer data it is
     * { "data": $json_value }
     * <p>
     * for a JWT Encoded Offer it is
     * {"data": $jwt_string, "data_integrity": "jwt"}
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
     * Expiration in unix epoch (since 1.1.1970) timestamp in seconds
     */
    @NotNull
    private Long tokenExpirationTimestamp;
    /**
     * Value used in the holder binding process to prevent replay attacks
     */
    private UUID nonce;
    /**
     * Value used to get the token for grant-type:pre-authorized_code
     */
    private UUID preAuthorizedCode;
    @NotNull
    private long offerExpirationTimestamp;
    private Instant credentialValidFrom;
    private Instant credentialValidUntil;
    /**
     * This claim is contained in the response if the Credential Issuer was unable to immediately issue the Credential.
     * Is removed after the Credential has been obtained by the Wallet
     */
    @JdbcTypeCode(SqlTypes.JSON)
    private CredentialRequest credentialRequest;

    @OneToMany(mappedBy = "offer")
    private Set<CredentialOfferStatus> offerStatusSet;

    public void markAsIssued() {
        this.invalidateOfferData();
        this.credentialStatus = CredentialStatus.ISSUED;
        log.info("Credential issued for offer {}. Management-ID is {}. ",
                this.metadataCredentialSupportedId, this.id);
    }

    public void markAsInProgress() {
        this.credentialStatus = CredentialStatus.IN_PROGRESS;
        if (this.accessToken == null) {
            this.accessToken = UUID.randomUUID();
        }
    }

    public void setTokenIssuanceTimestamp(long tokenTTL) {
        this.tokenExpirationTimestamp = Instant.now().plusSeconds(tokenTTL).getEpochSecond();
    }

    public void markAsExpired() {
        this.credentialStatus = CredentialStatus.EXPIRED;
        this.invalidateOfferData();
        log.info("Credential expired for offer {}. Management-ID is {}.", this.metadataCredentialSupportedId, this.id);
    }

    public void markAsDeferred(UUID transactionId,
                               CredentialRequest credentialRequest,
                               String holderPublicKey) {
        this.credentialStatus = CredentialStatus.DEFERRED;
        this.credentialRequest = credentialRequest;
        this.transactionId = transactionId;
        this.holderJWK = holderPublicKey;
        log.info("Deferred credential response for offer {}. Management-ID is {} and status is {}. ",
                this.metadataCredentialSupportedId, this.id, this.credentialStatus);
    }

    public boolean hasExpirationTimeStampPassed() {
        return Instant.now().isAfter(Instant.ofEpochSecond(this.offerExpirationTimestamp));
    }

    public boolean hasTokenExpirationPassed() {
        return this.tokenExpirationTimestamp != null && Instant.now().isAfter(Instant.ofEpochSecond(this.tokenExpirationTimestamp));
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
    }
}