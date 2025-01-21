package ch.admin.bj.swiyu.issuer.management.domain.credentialoffer;

import lombok.Getter;

public enum CredentialStatusType {
    OFFERED,
    CANCELLED,
    IN_PROGRESS,
    ISSUED,
    SUSPENDED,
    REVOKED,
    EXPIRED;

    public boolean isIssuedToHolder() {
        return this != OFFERED && this != IN_PROGRESS && this != CANCELLED;
    }

    public boolean isDuringHolderInteraction() {
        return this == IN_PROGRESS;
    }
}
