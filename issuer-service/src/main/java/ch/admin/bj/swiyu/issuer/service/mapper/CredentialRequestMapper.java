/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.service.mapper;

import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialRequestDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialResponseEncryptionDto;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialResponseEncryptionClass;
import lombok.experimental.UtilityClass;

@UtilityClass
public class CredentialRequestMapper {

    public static CredentialRequestClass toCredentialRequest(CredentialRequestDto dto) {
        return new CredentialRequestClass(
                dto.format(),
                dto.proof(),
                toCredentialResponseEncryption(dto.credentialResponseEncryption())
        );
    }

    public static CredentialRequestDto toCredentialRequest(CredentialRequestClass clazz) {

        if (clazz == null) {
            return null;
        }
        
        return new CredentialRequestDto(
                clazz.getFormat(),
                clazz.getProof(),
                toCredentialResponseEncryptionDto(clazz.getCredentialResponseEncryption())
        );
    }

    public static CredentialResponseEncryptionClass toCredentialResponseEncryption(CredentialResponseEncryptionDto credentialRequestDto) {
        if (credentialRequestDto == null) {
            return null;
        }

        return new CredentialResponseEncryptionClass(
                credentialRequestDto.jwk(),
                credentialRequestDto.alg(),
                credentialRequestDto.enc()
        );
    }

    public static CredentialResponseEncryptionDto toCredentialResponseEncryptionDto(CredentialResponseEncryptionClass credentialResponseEncryptionClass) {
        if (credentialResponseEncryptionClass == null) {
            return null;
        }

        return new CredentialResponseEncryptionDto(
                credentialResponseEncryptionClass.getJwk(),
                credentialResponseEncryptionClass.getAlg(),
                credentialResponseEncryptionClass.getEnc()
        );
    }
}