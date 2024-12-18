package ch.admin.bit.eid.issuer_management.domain.entities;

import ch.admin.bit.eid.issuer_management.enums.CredentialStatusEnum;
import ch.admin.bit.eid.issuer_management.exception.BadRequestException;
import com.google.gson.GsonBuilder;
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
import lombok.*;
import org.hibernate.annotations.Cascade;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Representation of a single offer and the vc which was created using that offer.
 * This object serves as a link between the business issuer and the issued verifiable credential (vc).
 */
@Entity
@Getter // do not apply generell setters on entities
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
    private CredentialStatusEnum credentialStatus;

    /**
     * ID String referencing the entry in the issuer metadata of the signer
     */
    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> metadataCredentialSupportedId;

    /**
     * the Credential Subject Data. Has the shape for unprotected data
     * <pre><code>
     * {
     *     "data": vc data json
     * }
     * </code></pre>
     * <p>
     * For data integrity protected data uses the shape
     * <pre><code>
     * {
     *     "data": jwt encoded vc data string,
     *     "data_integrity": "jwt"
     * }
     * </code></pre>
     */
    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> offerData;

    /**
     * Value used for the oid bearer token given to the holder
     */
    @NotNull
    private UUID accessToken;

    /**
     * Validity duration for the offer in seconds
     */
    private long offerExpirationTimestamp;

    /**
     * Value used in the holder binding process to prevent replay attacks
     */
    private UUID holderBindingNonce;

    private Instant credentialValidFrom;

    private Instant credentialValidUntil;

    /**
     * Link to what indexes on status lists are assigned to the vc
     */
    @OneToMany(mappedBy = "offer", fetch = FetchType.EAGER)
    @Cascade(org.hibernate.annotations.CascadeType.ALL)
    private Set<CredentialOfferStatus> offerStatusSet;

    public static Map<String, Object> readOfferData(Object offerData) {
        var metadata = new LinkedHashMap<String, Object>();
        if (offerData instanceof String) {
            metadata.put("data", offerData);
            metadata.put("data_integrity", "jwt");
        } else if (offerData instanceof Map) {
            metadata.put("data", new GsonBuilder().create().toJson(offerData));
        } else {
            throw new BadRequestException(String.format("Unsupported OfferData %s", offerData));
        }
        return metadata;
    }

    public void removeOfferData() {
        this.offerData = null;
    }

    public void changeStatus(CredentialStatusEnum credentialStatus) {
        this.credentialStatus = credentialStatus;
    }
}
