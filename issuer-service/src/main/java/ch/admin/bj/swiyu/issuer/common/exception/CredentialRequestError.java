package ch.admin.bj.swiyu.issuer.common.exception;

/**
 * If the Wallet is requesting the issuance of a Credential that is not
 * supported by the Credential Endpoint, the HTTP response MUST use the HTTP
 * status code 400 (Bad Request) and set the content type to application/json
 * with the following parameters in the JSON-encoded response body errors
 */
public enum CredentialRequestError {
    /**
     * The Credential Request is missing a required parameter, includes an
     * unsupported parameter or parameter value, repeats the same parameter, or is
     * otherwise malformed.
     */
    INVALID_CREDENTIAL_REQUEST,
    /**
     * Requested Credential Configuration is unknown
     */
    UNKNOWN_CREDENTIAL_CONFIGURATION,
    /**
     * Requested Credential identifier is unknown
     */
    UNKNOWN_CREDENTIAL_IDENTIFIER,
    /**
     * The proofs parameter in the Credential Request is invalid: (1) if the field
     * is missing, or (2) one of the provided key proofs is invalid, or (3) if at
     * least one of the key proofs does not contain a c_nonce value
     */
    INVALID_PROOF,
    /**
     * The proofs parameter in the Credential Request uses an invalid nonce: at
     * least one of the key proofs contains an invalid c_nonce value. The wallet
     * should retrieve a new c_nonce value
     */
    INVALID_NONCE,
    /**
     * This error occurs when the encryption parameters in the Credential Request
     * are either invalid or missing. In the latter case, it indicates that the
     * Credential Issuer requires the Credential Response to be sent encrypted, but
     * the Credential Request does not contain the necessary encryption parameters
     */
    INVALID_ENCRYPTION_PARAMETERS,
    /**
     * The Credential Request has not been accepted by the Credential Issuer. The
     * Wallet SHOULD treat this error as unrecoverable, meaning if received from a
     * Credential Issuer the Credential cannot be issued.
     */
    CREDENTIAL_REQUEST_DENIED,
    /**
     * The Deferred Credential Request contains an invalid transaction_id. This
     * error occurs when the transaction_id was not issued by the respective
     * Credential Issuer or it was already used to obtain a Credential.
     */
    INVALID_TRANSACTION_ID,
    @Deprecated(since = "OID4VCI 1.0")
    UNSUPPORTED_CREDENTIAL_TYPE,
    @Deprecated(since = "OID4VCI 1.0")
    UNSUPPORTED_CREDENTIAL_FORMAT,
    @Deprecated(since = "OID4VCI 1.0")
    ISSUANCE_PENDING,
}