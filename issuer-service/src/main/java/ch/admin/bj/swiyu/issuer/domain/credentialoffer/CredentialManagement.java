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
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.statemachine.StateMachine;
import org.springframework.statemachine.StateMachineEventResult;
import org.springframework.statemachine.support.DefaultStateMachineContext;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static ch.admin.bj.swiyu.issuer.common.config.CredentialStateMachineConfig.CredentialManagementEvent;

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

//    public void sendEvent(StateMachine<CredentialStatusManagementType, CredentialManagementEvent> stateMachine, CredentialManagementEvent event) {
//        // Set the current state in the state machine
//        stateMachine.getStateMachineAccessor().doWithAllRegions(access -> access.resetStateMachine(new DefaultStateMachineContext<>(this.credentialManagementStatus, null, null, null)));
//        // Send event
//        boolean success = stateMachine.sendEvent(event);
//        if (success) {
//            this.credentialManagementStatus = stateMachine.getState().getId();
//            log.info("Credential issued for {}. ", this.id);
//        } else {
//            throw new IllegalStateException("Transition failed");
//        }
//    }

    public void sendEventAndUpdateStatus(StateMachine<CredentialStatusManagementType, CredentialManagementEvent> stateMachine, CredentialManagementEvent event) {

            stateMachine.getStateMachineAccessor()
                    .doWithAllRegions(access ->
                            access.resetStateMachineReactively(
                                    new DefaultStateMachineContext<>(
                                            this.credentialManagementStatus,
                                            null,
                                            null,
                                            null
                                    )
                            ).block()
                    );

            StateMachineEventResult<CredentialStatusManagementType, CredentialManagementEvent> success = stateMachine
                    .sendEvent(
                            Mono.just(
                                    MessageBuilder
                                            .withPayload(event)
                                            .setHeader("credentialId", this.id)
                                            .setHeader("oldStatus", this.credentialManagementStatus)
                                            .build()
                            )
                    )
                    .blockLast();

        assert success != null;
        if (success.getResultType().equals(StateMachineEventResult.ResultType.ACCEPTED)) {
                this.credentialManagementStatus = stateMachine.getState().getId();
                log.info("Transaction accepted for: {}. New state = {}", success.getMessage(), this.credentialManagementStatus);
            } else {
                log.info("Transaction failed for: {}.", success.getMessage());
                throw new IllegalStateException("Transition failed for "+ success.getMessage());
            }
    }


    public UUID getLastValidLegacyNonce() {
        return this.isPreIssuanceProcess()
                // is normal issuance process -> get offer in progress and use this nonce
                ? this.getCredentialOffers().stream().filter(offer -> offer.getCredentialStatus() == CredentialOfferStatusType.IN_PROGRESS)
                .map(o -> o.getNonce())
                .findFirst()
                .orElseThrow()
                // is refresh
                : this.getCredentialOffers().stream().filter(offer -> offer.getCredentialStatus() == CredentialOfferStatusType.ISSUED)
                .map(o -> o.getNonce())
                .findFirst()
                .orElseThrow();
    }
}