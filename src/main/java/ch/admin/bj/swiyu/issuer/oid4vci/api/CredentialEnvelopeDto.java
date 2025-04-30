/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.api;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * Helper DTO providing the http content type alongside the credential
 */
@Getter
@AllArgsConstructor
@Schema(name = "CredentialEnvelope")
public class CredentialEnvelopeDto {
    private String contentType;
    private String oid4vciCredentialJson;
}
