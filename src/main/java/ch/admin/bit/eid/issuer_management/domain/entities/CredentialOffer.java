package ch.admin.bit.eid.issuer_management.domain.entities;

import ch.admin.bit.eid.issuer_management.enums.CredentialStatusEnum;
import ch.admin.bit.eid.issuer_management.exceptions.BadRequestException;
import com.google.gson.GsonBuilder;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.Cascade;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "credential_offer")
public class CredentialOffer {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Enumerated(EnumType.STRING)
    private CredentialStatusEnum credentialStatus;

    @JdbcTypeCode(SqlTypes.JSON)
    private List<String> metadataCredentialSupportedId;

    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> offerData;

    private UUID accessToken;

    private long offerExpirationTimestamp;

    private UUID holderBindingNonce;

    private LocalDateTime credentialValidFrom;

    private LocalDateTime credentialValidUntil;

    @OneToMany(mappedBy = "offer")
    @Cascade(org.hibernate.annotations.CascadeType.ALL)
    private Set<CredentialOfferStatus> offerStatusSet;


    public static class CredentialOfferBuilder {
        public CredentialOfferBuilder offerData(Object offerData) {
            Map<String, Object> metadata = new LinkedHashMap<>();
            if (offerData instanceof String) {
                metadata.put("data", offerData);
                metadata.put("data_integrity", "jwt");
            } else if (offerData instanceof Map) {
                metadata.put("data", new GsonBuilder().create().toJson(offerData));
            } else {
                throw new BadRequestException(String.format("Unsupported OfferData %s", offerData));
            }
            this.offerData = metadata;
            return this;
        }
    }
}
