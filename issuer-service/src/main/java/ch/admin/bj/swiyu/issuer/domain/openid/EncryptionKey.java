package ch.admin.bj.swiyu.issuer.domain.openid;


import com.nimbusds.jose.jwk.JWKSet;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.text.ParseException;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * Technical table to share ephemeral encryption keys
 */
@Entity
@Getter
@Setter
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED) // JPA
@AllArgsConstructor
@Table(name = "encryption_key")
public class EncryptionKey {
    @Id
    private UUID id;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "jwks", columnDefinition = "jsonb")
    private Map<String, Object> jwks;

    @Column(name = "creation_timestamp")
    private Instant creationTimestamp;

    public JWKSet getJwkSet() {
        try {
            return JWKSet.parse(jwks);
        } catch (ParseException e) {
            throw new IllegalStateException("Corrupted keyset in database for id %s".formatted(id), e);
        }
    }
}
