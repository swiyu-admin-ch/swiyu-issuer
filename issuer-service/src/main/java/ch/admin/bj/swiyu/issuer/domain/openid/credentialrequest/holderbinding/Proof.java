package ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@AllArgsConstructor
@Getter
public abstract class Proof {
    public final ProofType proofType;

    public abstract boolean isValidHolderBinding(String issuerId, List<String> supportedSigningAlgorithms, Long tokenExpirationTimestamp);

    public abstract String getNonce();

    public abstract String getBinding();

    public abstract ProofType getProofType();
}