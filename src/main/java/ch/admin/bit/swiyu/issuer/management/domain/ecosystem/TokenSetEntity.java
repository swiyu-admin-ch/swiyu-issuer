package ch.admin.bit.swiyu.issuer.management.domain.ecosystem;

import ch.admin.bit.swiyu.issuer.management.enums.EcosystemApiEnum;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;

import java.time.Instant;

/**
 * Entity to manage the swiyu  provider provided tokens.
 * <warning>No instance of this class should not be accessed outside the TokenManager class.</warning>
 */
@Entity
public class TokenSetEntity {
    @Id
    @Enumerated(EnumType.STRING)
    EcosystemApiEnum apiTarget;

    @Column(nullable = true)
    String refreshToken;

    @Column(nullable = false)
    String accessToken;

    @Column(nullable = false)
    Instant lastRefresh;

    public TokenSetEntity apply(EcosystemApiEnum apiTarget, TokenApi.TokenResponse tokenResponse) {
        this.apiTarget = apiTarget;
        this.refreshToken = tokenResponse.refresh_token();
        this.accessToken = tokenResponse.access_token();
        this.lastRefresh = Instant.now();
        return this;
    }
}
