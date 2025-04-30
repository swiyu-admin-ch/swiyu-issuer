/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.common.exception;

public enum CredentialRequestError {
    INVALID_CREDENTIAL_REQUEST,
    UNSUPPORTED_CREDENTIAL_TYPE,
    UNSUPPORTED_CREDENTIAL_FORMAT,
    INVALID_PROOF,
    INVALID_ENCRYPTION_PARAMETERS,
    ISSUANCE_PENDING,
    INVALID_TRANSACTION_ID
}