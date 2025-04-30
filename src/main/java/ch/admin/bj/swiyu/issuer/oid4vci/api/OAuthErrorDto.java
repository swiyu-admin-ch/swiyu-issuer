/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.api;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;
import org.springframework.http.HttpStatus;

/**
 * Possible Errors for an OAuth Error Response
 */
@Schema(name = "OAuthError", enumAsRef = true)
@Getter
public enum OAuthErrorDto {
    INVALID_REQUEST(HttpStatus.BAD_REQUEST, "invalid_request"),
    INVALID_CLIENT(HttpStatus.UNAUTHORIZED, "invalid_client"),
    INVALID_GRANT(HttpStatus.BAD_REQUEST, "invalid_grant"),
    INVALID_TOKEN(HttpStatus.BAD_REQUEST, "invalid_token"),
    UNAUTHORIZED_CLIENT(HttpStatus.BAD_REQUEST, "unauthorized_client"),
    UNSUPPORTED_GRANT_TYPE(HttpStatus.BAD_REQUEST, "unsupported_grant_type"),
    INVALID_SCOPE(HttpStatus.BAD_REQUEST, "invalid_scope");

    private final HttpStatus httpStatus;
    private final String errorCode;

    OAuthErrorDto(HttpStatus httpStatus, String errorCode) {
        this.httpStatus = httpStatus;
        this.errorCode = errorCode;
    }


    @Override
    public String toString() {
        return this.errorCode;
    }
}