/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.domain.ecosystem;

import java.time.Instant;

import jakarta.persistence.*;
import lombok.Getter;

/**
 * Entity to manage the swiyu provider provided tokens.
 * <warning>No instance of this class should not be accessed outside the
 * TokenManager class.</warning>
 */

@Entity
@Getter
@Table(name = "token_set")
public class TokenSet {
    @Id
    @Enumerated(EnumType.STRING)
    EcosystemApiType apiTarget;

    @Column(nullable = true)
    String refreshToken;

    @Column(nullable = false)
    String accessToken;

    @Column(nullable = false)
    Instant lastRefresh;

    public void apply(EcosystemApiType apiTarget, TokenApi.TokenResponse tokenResponse) {
        this.apiTarget = apiTarget;
        this.refreshToken = tokenResponse.refresh_token();
        this.accessToken = tokenResponse.access_token();
        this.lastRefresh = Instant.now();
    }
}
