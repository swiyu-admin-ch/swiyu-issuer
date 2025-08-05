/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.service.mapper;

import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialRequestDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialResponseEncryptionDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2.CredentialRequestDtoV2;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialResponseEncryptionClass;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofType;
import lombok.experimental.UtilityClass;

import java.util.Map;

import static ch.admin.bj.swiyu.issuer.service.SdJwtCredential.SD_JWT_FORMAT;

@UtilityClass
public class CredentialRequestMapper {

    public static CredentialRequestClass toCredentialRequest(CredentialRequestDto dto) {
        return new CredentialRequestClass(
                dto.format(),
                dto.proof(),
                toCredentialResponseEncryption(dto.credentialResponseEncryption())
        );
    }

    public static CredentialRequestClass toCredentialRequest(CredentialRequestDtoV2 dto) {
        return new CredentialRequestClass(
                SD_JWT_FORMAT,
                dto.proofs() == null ? null : Map.of(ProofType.JWT.toString(), dto.proofs().jwt()),
                toCredentialResponseEncryption(dto.credentialResponseEncryption()),
                dto.credentialConfigurationId()
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