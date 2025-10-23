package ch.admin.bj.swiyu.issuer.common.exception;

import lombok.Getter;

public enum DemonstratingProofOfPossessionError {
    USE_DPOP_NONCE("use_dpop_nonce"),
    INVALID_DPOP_PROOF("invalid_dpop_proof");

    @Getter
    private final String name;

    DemonstratingProofOfPossessionError(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return getName();
    }
}
