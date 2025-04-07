/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.domain.credentialoffer;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Map;

@Getter
@AllArgsConstructor
public class CredentialRequest {

    private String format;

    private Map<String, Object> proof;

    private CredentialResponseEncryption credentialResponseEncryption;
}