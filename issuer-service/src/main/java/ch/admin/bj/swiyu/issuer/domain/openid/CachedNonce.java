package ch.admin.bj.swiyu.issuer.domain.openid;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.UUID;

@Entity
@Getter
@Setter
@Builder
@NoArgsConstructor(access = AccessLevel.PROTECTED) // JPA
@AllArgsConstructor
@EntityListeners(AuditingEntityListener.class)
@Table(name = "nonce_cache")
public class CachedNonce {
    @Id
    UUID nonce;
    @Column
    private Instant timestamp;
}
