/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.credentialrequest;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.validation.annotation.Validated;

import java.util.Map;

@Validated
@Data
@AllArgsConstructor
public class CredentialResponseEncryption {
    private Map<String, Object> jwk;
    private String alg;
    private String enc;
}