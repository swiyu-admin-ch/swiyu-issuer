package ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;
import java.util.UUID;

@AllArgsConstructor
@Getter
public abstract class Proof {
    public final ProofType proofType;

    public abstract boolean isValidHolderBinding(String issuerId, List<String> supportedSigningAlgorithms, UUID nonce, Long tokenExpirationTimestamp);

    public abstract String getNonce();

    public abstract String getBinding();

    public abstract ProofType getProofType();
}