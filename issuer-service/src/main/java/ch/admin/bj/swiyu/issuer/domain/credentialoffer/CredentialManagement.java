package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import ch.admin.bj.swiyu.issuer.domain.AuditMetadata;
import jakarta.annotation.Nullable;
import jakarta.persistence.*;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
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
@EntityListeners({AuditingEntityListener.class})
public class CredentialManagement {
    @Embedded
    @Valid
    private final AuditMetadata auditMetadata = new AuditMetadata();

    @Id
    @Builder.Default
    private UUID id = UUID.randomUUID(); // Generate the ID manually

    /**
     * OAuth 2.0 access token
     */
    @Nullable
    @Column(name = "access_token")
    private UUID accessToken;

    /**
     * Access token expiration in unix epoch (since 1.1.1970) timestamp in seconds
     */
    @Nullable
    @Column(name = "access_token_expiration_timestamp")
    private Long accessTokenExpirationTimestamp;

    /**
     * OAuth 2.0 refresh token
     * Can be null, if refresh was not enabled when the access token was collected
     */
    @Nullable
    @Column(name = "refresh_token")
    private UUID refreshToken;


    /**
     * @return true, if the access token has expired (is not valid anymore)
     */
    public boolean hasAccessTokenExpirationPassed() {
        return Instant.now().isAfter(Instant.ofEpochSecond(this.accessTokenExpirationTimestamp));
    }
}
