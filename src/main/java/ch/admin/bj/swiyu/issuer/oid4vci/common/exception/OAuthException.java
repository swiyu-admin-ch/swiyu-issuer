/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.common.exception;

import lombok.Getter;

@Getter
public class OAuthException extends RuntimeException {

    private final OAuthError error;

    public OAuthException(OAuthError error, String message) {
        super(message);
        this.error = error;
    }

    public static OAuthException invalidToken(String detailMessage) {
        return new OAuthException(OAuthError.INVALID_TOKEN, detailMessage);
    }

    public static OAuthException invalidRequest(String detailMessage) {
        return new OAuthException(OAuthError.INVALID_REQUEST, detailMessage);
    }

    public static OAuthException invalidGrant(String detailMessage) {
        return new OAuthException(OAuthError.INVALID_GRANT, detailMessage);
    }


}