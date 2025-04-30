/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.api;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;

import java.util.Map;

/**
 * information for encrypting the Credential Response.
 */
@Schema(name = "CredentialResponseEncryption")
public record CredentialResponseEncryptionDto(
        @NotNull
        Map<String, Object> jwk,
        @NotNull
        String alg,
        @NotNull
        String enc) {
}