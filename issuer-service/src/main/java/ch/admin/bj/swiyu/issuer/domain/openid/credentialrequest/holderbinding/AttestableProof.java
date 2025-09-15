package ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding;

@FunctionalInterface
public interface AttestableProof {
    /**
     * @return The attestation as base 64 encoded jwt
     */
    String getAttestationJwt();
}
