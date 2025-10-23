package ch.admin.bj.swiyu.issuer.common.exception;

import lombok.Getter;

@Getter
public class DemonstratingProofOfPossessionException extends RuntimeException {
    private final DemonstratingProofOfPossessionError dpopError;

    public DemonstratingProofOfPossessionException(String message, DemonstratingProofOfPossessionError dpopError) {
        super(message);
        this.dpopError = dpopError;
    }

    public DemonstratingProofOfPossessionException(String message, DemonstratingProofOfPossessionError dpopError, Exception e) {
        super(message, e);
        this.dpopError = dpopError;
    }
}
