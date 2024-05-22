package ch.admin.bit.eid.issuer_management.models.entities;

import ch.admin.bit.eid.issuer_management.enums.CredentialStatusEnum;
import ch.admin.bit.eid.issuer_management.util.JsonConverter;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.ColumnTransformer;

import java.time.Instant;
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

    private CredentialStatusEnum credentialStatus;

    private String metadataCredentialSupportedId;

    @Column(columnDefinition = "json")
    @Convert(converter = JsonConverter.class) // TODO: Decide what happens https://www.baeldung.com/hibernate-persist-json-object
    @ColumnTransformer(write = "?::json")
    private Object offerData;

    @JsonProperty("access_token")
    private UUID accessToken;

    @JsonProperty("offer_expiration_timestamp")
    private long offerExpirationTimestamp;

    @JsonProperty("holder_binding_nonce")
    private UUID holderBindingNonce;

    @JsonProperty("credential_valid_from")
    private Instant credentialValidFrom;

    @JsonProperty("credential_valid_until")
    private Instant credentialValidUntil;
}
