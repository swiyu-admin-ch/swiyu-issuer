package ch.admin.bj.swiyu.issuer.dto.oid4vci;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(name = "CredentialRequestError", enumAsRef = true)
public enum CredentialRequestErrorDto {
    INVALID_CREDENTIAL_REQUEST("invalid_credential_request"),
    UNKNOWN_CREDENTIAL_CONFIGURATION("unknown_credential_configuration"),
    UNKNOWN_CREDENTIAL_IDENTIFIER("unknown_credential_identifier"),
    INVALID_PROOF("invalid_proof"),
    INVALID_NONCE("invalid_nonce"),
    INVALID_ENCRYPTION_PARAMETERS("invalid_encryption_parameters"),
    CREDENTIAL_REQUEST_DENIED("credential_request_denied"),
    INVALID_TRANSACTION_ID("invalid_transaction_id"),
    @Deprecated(since = "OID4VCI 1.0")
    UNSUPPORTED_CREDENTIAL_TYPE("unsupported_credential_type"),
    @Deprecated(since = "OID4VCI 1.0")
    UNSUPPORTED_CREDENTIAL_FORMAT("unsupported_credential_format"),
    @Deprecated(since = "OID4VCI 1.0")
    ISSUANCE_PENDING("issuance_pending");

    private final String errorCode;

    CredentialRequestErrorDto(String errorCode) {
        this.errorCode = errorCode;
    }

    @Override
    public String toString() {
        return this.errorCode;
    }
}