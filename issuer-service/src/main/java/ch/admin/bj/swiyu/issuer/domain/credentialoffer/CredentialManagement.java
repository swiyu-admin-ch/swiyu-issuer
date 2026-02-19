package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import ch.admin.bj.swiyu.issuer.domain.AuditMetadata;
import jakarta.annotation.Nullable;
import jakarta.persistence.*;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.*;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.Instant;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Entity
@Getter
@Setter
@Builder
@Slf4j
@NoArgsConstructor(access = AccessLevel.PROTECTED) // JPA
@AllArgsConstructor // test data
@EntityListeners(AuditingEntityListener.class)
@Table(name = "credential_management")
public class CredentialManagement {

    @Embedded
    @Valid
    private final AuditMetadata auditMetadata = new AuditMetadata();

    @Id
    private UUID id;

    @NotNull
    @Enumerated(EnumType.STRING)
    @Setter(AccessLevel.NONE) // Kein Lombok-Setter für dieses Feld
    private CredentialStatusManagementType credentialManagementStatus;

    /**
     * Expiration in unix epoch (since 1.1.1970) timestamp in seconds
     */
    @Nullable
    private Long accessTokenExpirationTimestamp;

    /**
     * Value used for the oid bearer token given to the holder
     */
    @NotNull
    private UUID accessToken;

    /**
     * OAuth refresh token for the offer
     */
    @Nullable
    @Column(name = "refresh_token")
    private UUID refreshToken;

    private Integer renewalRequestCnt;

    private Integer renewalResponseCnt;

    /**
     * Wallet Public Key used for DPoP header JWT
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private Map<String, Object> dpopKey;

    @OneToMany(mappedBy = "credentialManagement", fetch = FetchType.LAZY, cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private Set<CredentialOffer> credentialOffers = new HashSet<>();

    public void setDPoPKey(Map<String, Object> dPoPKey) {
        this.dpopKey = dPoPKey;
    }

    public void setTokenIssuanceTimestamp(long tokenTTL) {
        this.accessTokenExpirationTimestamp = Instant.now().plusSeconds(tokenTTL).getEpochSecond();
    }

    public boolean hasTokenExpirationPassed() {
        return this.accessTokenExpirationTimestamp == null
                || Instant.now().isAfter(Instant.ofEpochSecond(this.accessTokenExpirationTimestamp));
    }

    public boolean isPreIssuanceProcess() {
        return this.credentialManagementStatus == CredentialStatusManagementType.INIT;
    }

    // Helper to keep both sides in sync when adding/removing offers
    public void addCredentialOffer(CredentialOffer offer) {
        if (offer == null) return;
        this.credentialOffers.add(offer);
        offer.setCredentialManagement(this);
    }

    /**
     * Sets the status of this credential management entity.
     * <p>
     * <b>Intended for use by {@link CredentialStateMachine} only.</b>
     * Do not use outside the state machine context to ensure correct state transitions.
     *
     * @param credentialManagementStatus the new status to set
     */
    void setCredentialManagementStatus(CredentialStatusManagementType credentialManagementStatus) {
        this.credentialManagementStatus = credentialManagementStatus;
    }

    /**
     * Sets the status of this credential management entity.
     * <p>
     * <b>Intended for test usage only.</b>
     * Do not use in production code.
     *
     * @param credentialManagementStatus the new status to set
     */
    public void setCredentialManagementStatusJustForTestUsage(CredentialStatusManagementType credentialManagementStatus) {
        this.credentialManagementStatus = credentialManagementStatus;
    }
}