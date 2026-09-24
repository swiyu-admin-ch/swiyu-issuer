package ch.admin.bj.swiyu.issuer.common.exception;

public class InvalidTxCodeException extends OAuthException {

    public InvalidTxCodeException(OAuthError error, String message) {
        super(error, message);
    }

    public static InvalidTxCodeException invalidTxCode() {
        return new InvalidTxCodeException(OAuthError.INVALID_TX_CODE, "The provided tx_code does not match the expected value");
    }

    public static InvalidTxCodeException tooManyInvalidTxCodeException() {
        return new InvalidTxCodeException(OAuthError.INVALID_GRANT, "Too many incorrect tx_code were used. Offer has been invalidated.");
    }
}
