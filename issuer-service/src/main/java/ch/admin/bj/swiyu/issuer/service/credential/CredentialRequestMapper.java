/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.service.credential;

import ch.admin.bj.swiyu.issuer.dto.oid4vci.CredentialEndpointRequestDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.CredentialResponseEncryptionDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.issuance_v2.CredentialEndpointRequestDtoV2;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialResponseEncryptionClass;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofType;
import lombok.experimental.UtilityClass;

import java.util.Map;

import static ch.admin.bj.swiyu.issuer.service.SdJwtCredential.SD_JWT_FORMAT;

@UtilityClass
public class CredentialRequestMapper {

    public static CredentialRequestClass toCredentialRequest(CredentialEndpointRequestDto dto) {
        return new CredentialRequestClass(
                dto.format(),
                dto.proof(),
                toCredentialResponseEncryption(dto.credentialResponseEncryption())
        );
    }

    public static CredentialRequestClass toCredentialRequest(CredentialEndpointRequestDtoV2 dto) {
        return new CredentialRequestClass(
                SD_JWT_FORMAT,
                dto.proofs() == null ? null : Map.of(ProofType.JWT.toString(), dto.proofs().jwt()),
                toCredentialResponseEncryption(dto.credentialResponseEncryption()),
                dto.credentialConfigurationId()
        );
    }

    public static CredentialEndpointRequestDto toCredentialRequest(CredentialRequestClass clazz) {

        if (clazz == null) {
            return null;
        }

        return new CredentialEndpointRequestDto(
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