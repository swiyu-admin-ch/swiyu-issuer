package ch.admin.bit.eid.issuer_management.models.entities;

import ch.admin.bit.eid.issuer_management.enums.CredentialStatusEnum;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
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
}
