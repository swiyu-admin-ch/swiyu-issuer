package ch.admin.bj.swiyu.issuer.common.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Errors for <a href="https://datatracker.ietf.org/doc/html/rfc9449#section-12.2">rfc9449</a>
 */
@RequiredArgsConstructor
@Getter
public enum DemonstratingProofOfPossessionError {
    USE_DPOP_NONCE("use_dpop_nonce"),
    INVALID_DPOP_PROOF("invalid_dpop_proof");

    private final String name;

    @Override
    public String toString() {
        return getName();
    }
}
