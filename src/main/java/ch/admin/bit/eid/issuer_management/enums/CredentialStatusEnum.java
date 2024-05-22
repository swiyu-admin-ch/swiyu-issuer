package ch.admin.bit.eid.issuer_management.enums;

public enum CredentialStatusEnum {
    OFFERED("Offered"),
    CANCELLED("Cancelled"),
    IN_PROGRESS("Claiming in Progress"),
    ISSUED("Issued"),
    SUSPENDED("Suspended"),
    REVOKED("Revoked"),
    EXPIRED("Expired");

    private String displayName;

    CredentialStatusEnum(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    public boolean isPostHolderInteraction() {
        return this != OFFERED && this != IN_PROGRESS && this != CANCELLED;
    }

    public boolean isDuringHolderInteraction() {
        return this == IN_PROGRESS;
    }
}
