package ch.admin.bj.swiyu.issuer.common.exception;

/**
 * Possible Errors for an OAuth Error Response
 */
public enum OAuthError {
    INVALID_REQUEST,
    INVALID_CLIENT,
    INVALID_GRANT,
    UNAUTHORIZED_CLIENT,
    UNSUPPORTED_GRANT_TYPE,
    INVALID_TOKEN,
    INVALID_SCOPE,
    /**
     * Swiss Profile Issuance 1.0 Custom Error<br>
     * Issuers SHOULD indiciate the wallet to reattempt entering a correct tx_code using 
     * the error code in the Token Response invalid_tx_code instead of invalid_grant.
     */
    INVALID_TX_CODE;
}