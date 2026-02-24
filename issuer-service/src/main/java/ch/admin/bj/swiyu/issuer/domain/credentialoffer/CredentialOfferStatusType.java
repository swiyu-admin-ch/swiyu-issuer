package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import java.util.List;
import java.util.Set;

import lombok.Getter;

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

    private static final Set<CredentialOfferStatusType> PROCESSABLE_STATES =
            Set.of(OFFERED, IN_PROGRESS, DEFERRED, READY, REQUESTED);

    private static final Set<CredentialOfferStatusType> TERMINAL_STATES =
            Set.of(EXPIRED, CANCELLED, ISSUED);

    private static final List<CredentialOfferStatusType> EXPIRABLE_STATES = List.of(CredentialOfferStatusType.OFFERED,
            CredentialOfferStatusType.IN_PROGRESS,
            CredentialOfferStatusType.DEFERRED,
            CredentialOfferStatusType.READY,
            CredentialOfferStatusType.REQUESTED);

    CredentialOfferStatusType(String displayName) {
        this.displayName = displayName;
    }

    /**
     * @return List of CredentialStatusType which can lead to "expire"
     */
    public static List<CredentialOfferStatusType> getExpirableStates() {
        return EXPIRABLE_STATES;
    }

    @Override
    public String toString() {
        return this.getDisplayName();
    }

    public boolean isProcessable() {
        return getProcessableStates().contains(this);
    }

    /**
     * States that are not init and not terminal
     *
     * @return
     */
    public static Set<CredentialOfferStatusType> getProcessableStates() {
        return PROCESSABLE_STATES;
    }

    public static Set<CredentialOfferStatusType> getTerminalStates() {
        return TERMINAL_STATES;
    }

    public boolean isTerminalState() {
        return getTerminalStates().contains(this);
    }
}