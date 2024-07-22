package ch.admin.bit.eid.issuer_management.models.entities;

import ch.admin.bit.eid.issuer_management.enums.CredentialStatusEnum;
import ch.admin.bit.eid.issuer_management.exceptions.BadRequestException;
import com.google.gson.GsonBuilder;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "credential_offer")
public class CredentialOfferEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Enumerated(EnumType.STRING)
    private CredentialStatusEnum credentialStatus;

    private String metadataCredentialSupportedId;

    @JdbcTypeCode(SqlTypes.JSON)
    private Map<String, Object> offerData;

    private UUID accessToken;

    private long offerExpirationTimestamp;

    private UUID holderBindingNonce;

    private Instant credentialValidFrom;

    private Instant credentialValidUntil;

    public static class CredentialOfferEntityBuilder {
        public CredentialOfferEntityBuilder offerData(Object offerData){
            Map<String, Object> metadata = new LinkedHashMap<>();
            if (offerData instanceof String) {
                metadata.put("data", offerData);
                metadata.put("data_integrity", "jwt");
            }else if (offerData instanceof Map) {
                metadata.put("data", new GsonBuilder().create().toJson(offerData));
            } else {
                throw new BadRequestException(String.format("Unsupported OfferData %s", offerData));
            }
            this.offerData = metadata;
            return this;
        }
    }
}
