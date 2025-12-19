package ch.admin.bj.swiyu.issuer.migration.domain;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.util.UUID;

@Entity
@Table(name = "credential_offer")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CredentialOfferV13Entity {

    @Id
    private UUID id;

    @Column(nullable = false)
    private String credentialStatus;

    @Column(name = "access_token")
    private UUID accessToken;

    @Column(name = "refresh_token")
    private UUID refreshToken;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "dpop_key")
    private String dpopKey;

    @Column(name = "token_expiration_timestamp")
    private Long tokenExpirationTimestamp;

    @Column(name = "nonce")
    private UUID nonce;
}
