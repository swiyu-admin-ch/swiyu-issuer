/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.dto.exception.ApiErrorDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.CredentialRequestErrorDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.OAuthErrorDto;
import ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthError;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import lombok.experimental.UtilityClass;
import org.springframework.http.HttpStatus;

@UtilityClass
public class CredentialMapper {

    public static ApiErrorDto oauthErrorToApiErrorDto(OAuthException exception) {
        var error = toOAuthErrorDto(exception.getError());

        return ApiErrorDto.builder()
                .errorCode(error.name())
                .errorDescription(exception.getMessage())
                .status(error.getHttpStatus())
                .build();
    }

    public static OAuthErrorDto toOAuthErrorDto(OAuthError error) {
        return switch (error) {
            case INVALID_REQUEST -> OAuthErrorDto.INVALID_REQUEST;
            case INVALID_CLIENT -> OAuthErrorDto.INVALID_CLIENT;
            case INVALID_GRANT -> OAuthErrorDto.INVALID_GRANT;
            case INVALID_TOKEN -> OAuthErrorDto.INVALID_TOKEN;
            case UNAUTHORIZED_CLIENT -> OAuthErrorDto.UNAUTHORIZED_CLIENT;
            case UNSUPPORTED_GRANT_TYPE -> OAuthErrorDto.UNSUPPORTED_GRANT_TYPE;
            case INVALID_SCOPE -> OAuthErrorDto.INVALID_SCOPE;
        };
    }

    public static ApiErrorDto toCredentialRequestErrorResponseDto(Oid4vcException exception) {
        return ApiErrorDto.builder()
                .errorCode(toCredentialRequestError(exception.getError()).name())
                .errorDescription(exception.getMessage())
                .status(HttpStatus.BAD_REQUEST)
                .build();
    }

    public static CredentialRequestErrorDto toCredentialRequestError(CredentialRequestError source) {
        return switch (source) {
            case INVALID_CREDENTIAL_REQUEST -> CredentialRequestErrorDto.INVALID_CREDENTIAL_REQUEST;
            case UNSUPPORTED_CREDENTIAL_TYPE -> CredentialRequestErrorDto.UNSUPPORTED_CREDENTIAL_TYPE;
            case UNSUPPORTED_CREDENTIAL_FORMAT -> CredentialRequestErrorDto.UNSUPPORTED_CREDENTIAL_FORMAT;
            case INVALID_PROOF -> CredentialRequestErrorDto.INVALID_PROOF;
            case INVALID_ENCRYPTION_PARAMETERS -> CredentialRequestErrorDto.INVALID_ENCRYPTION_PARAMETERS;
            case ISSUANCE_PENDING -> CredentialRequestErrorDto.ISSUANCE_PENDING;
            case INVALID_TRANSACTION_ID -> CredentialRequestErrorDto.INVALID_TRANSACTION_ID;
            case CREDENTIAL_REQUEST_DENIED -> CredentialRequestErrorDto.CREDENTIAL_REQUEST_DENIED;
        };
    }
}