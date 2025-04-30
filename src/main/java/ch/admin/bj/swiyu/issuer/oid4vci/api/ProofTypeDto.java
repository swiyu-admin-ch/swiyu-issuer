/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.api;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
@Schema(name = "ProofType")
public enum ProofTypeDto {
    JWT("jwt", "openid4vci-proof+jwt");

    private final String displayName;
    /**
     * REQUIRED "typ": claim
     */
    private final String claimTyp;
}