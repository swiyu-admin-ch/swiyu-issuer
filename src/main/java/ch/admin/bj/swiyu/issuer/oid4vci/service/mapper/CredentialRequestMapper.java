/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.service.mapper;

import ch.admin.bj.swiyu.issuer.oid4vci.api.CredentialRequestDto;
import ch.admin.bj.swiyu.issuer.oid4vci.api.CredentialResponseEncryptionDto;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.credentialrequest.CredentialRequest;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.credentialrequest.CredentialResponseEncryption;
import lombok.experimental.UtilityClass;

@UtilityClass
public class CredentialRequestMapper {

    public static CredentialRequest toCredentialRequest(CredentialRequestDto dto) {
        return new CredentialRequest(
                dto.format(),
                dto.proof(),
                toCredentialResponseEncryption(dto.credentialResponseEncryption())
        );
    }

    public static CredentialResponseEncryption toCredentialResponseEncryption(CredentialResponseEncryptionDto credentialRequestDto) {
        if (credentialRequestDto == null) {
            return null;
        }

        return new CredentialResponseEncryption(
                credentialRequestDto.jwk(),
                credentialRequestDto.alg(),
                credentialRequestDto.enc()
        );
    }
}