/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.api;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(name = "CredentialRequestError", enumAsRef = true)
public enum CredentialRequestErrorDto {
    INVALID_CREDENTIAL_REQUEST("invalid_credential_request"),
    UNSUPPORTED_CREDENTIAL_TYPE("unsupported_credential_type"),
    UNSUPPORTED_CREDENTIAL_FORMAT("unsupported_credential_format"),
    INVALID_PROOF("invalid_proof"),
    INVALID_ENCRYPTION_PARAMETERS("invalid_encryption_parameters"),
    ISSUANCE_PENDING("issuance_pending"),
    INVALID_TRANSACTION_ID("invalid_transaction_id");

    private final String errorCode;

    CredentialRequestErrorDto(String errorCode) {
        this.errorCode = errorCode;
    }

    @Override
    public String toString() {
        return this.errorCode;
    }
}