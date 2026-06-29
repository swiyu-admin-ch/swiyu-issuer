package ch.admin.bj.swiyu.issuer.domain.credentialoffer.statemachine;

import lombok.Getter;

/**
 * Constants and event enumerations shared across credential state machines.
 *
 * <p>State machine construction has been moved to {@link CredentialStateMachineFactory}
 * to provide isolated, per-request instances instead of shared singletons.</p>
 */
public final class CredentialStateMachineConfig {

    public static final String CREDENTIAL_OFFER_HEADER = "credential_offer";
    public static final String CREDENTIAL_MANAGEMENT_HEADER = "credential_management";

    private CredentialStateMachineConfig() {
    }

    /**
     * Events for the credential management state machine.
     */
    public enum CredentialManagementEvent {
        ISSUE,
        SUSPEND,
        REVOKE
    }

    /**
     * Events for the credential offer state machine.
     */
    @Getter
    public enum CredentialOfferEvent {
        CREATED("Created at start"),
        OFFER("Offer"),
        CLAIM("Claim"),
        DEFER("Defer"),
        READY("Ready"),
        ISSUE("Issue"),
        EXPIRE("Expire"),
        CANCEL("Cancel"),
        REQUEST("Request");

        private final String displayName;

        CredentialOfferEvent(String displayName) {
            this.displayName = displayName;
        }
    }
}
