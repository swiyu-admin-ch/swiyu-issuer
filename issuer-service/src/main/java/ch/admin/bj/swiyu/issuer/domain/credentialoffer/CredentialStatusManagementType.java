package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import java.util.List;

public enum CredentialStatusManagementType {
    INIT,
    ISSUED,
    SUSPENDED,
    REVOKED;

    private static final List<CredentialStatusManagementType> POST_ISSUANCE_STATES = List.of(ISSUED, SUSPENDED, REVOKED);

    public boolean isIssued() {
        return getPostIssuanceStates().contains(this);
    }

    public List<CredentialStatusManagementType> getPostIssuanceStates() {
        return POST_ISSUANCE_STATES;
    }
}