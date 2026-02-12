package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import lombok.Getter;

import java.util.List;

@Getter
public enum CredentialOfferStatusType {
    INIT("INIT"),
    OFFERED("Offered"),
    CANCELLED("Cancelled"),
    IN_PROGRESS("Claiming_in_Progress"),
    // Status necessary for deferred flow
    DEFERRED("Deferred"),
    READY("Ready"),
    ISSUED("Issued"),
    // status only used for renewal flow
    REQUESTED("Requested"),
    EXPIRED("Expired");

    private final String displayName;

    CredentialOfferStatusType(String displayName) {
        this.displayName = displayName;
    }

    /**
     * @return List of CredentialStatusType which can lead to "expire"
     */
    public static List<CredentialOfferStatusType> getExpirableStates() {
        return List.of(CredentialOfferStatusType.OFFERED,
                CredentialOfferStatusType.IN_PROGRESS,
                CredentialOfferStatusType.DEFERRED,
                CredentialOfferStatusType.READY,
                CredentialOfferStatusType.REQUESTED);
    }

    @Override
    public String toString() {
        return this.getDisplayName();
    }

    public boolean isProcessable() {
        return this == OFFERED ||
                this == IN_PROGRESS ||
                this == DEFERRED ||
                this == READY ||
                this == REQUESTED;
    }

    public boolean isTerminalState() {
        return this == EXPIRED || this == CANCELLED || this == ISSUED;
    }
}