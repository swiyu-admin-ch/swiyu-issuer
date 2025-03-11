/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.domain.credentialoffer;

import ch.admin.bj.swiyu.issuer.management.common.exception.BadRequestException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Representation of a single offer and the vc which was created using that
 * offer.
 * This object serves as a link between the business issuer and the issued
 * verifiable credential (vc).
 */
@Entity
@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "credential_offer")
public class CredentialOffer {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

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
     * Expiration in unix epoch (since 1.1.1970) timestamp in seconds
     */
    private long offerExpirationTimestamp;

    /**
     * Value used in the holder binding process to prevent replay attacks
     */
    private UUID nonce;

    /**
     * Value used to get the token for grant-type:pre-authorized_code
     */
    private UUID preAuthorizedCode;

    private Long tokenExpirationTimestamp;

    private Instant credentialValidFrom;

    private Instant credentialValidUntil;

    /**
     * Link to what indexes on status lists are assigned to the vc
     */
    @OneToMany(mappedBy = "offer", fetch = FetchType.EAGER)
    private Set<CredentialOfferStatus> offerStatusSet;

    /**
     * Read the offer data depending on input type and add it to offer
     *
     * @param offerData can be string or map -> other will throw exception
     * @return offerdata map
     */
    public static Map<String, Object> readOfferData(Object offerData) {
        if (offerData instanceof String) {
            return readOfferDataString((String) offerData);
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
}
