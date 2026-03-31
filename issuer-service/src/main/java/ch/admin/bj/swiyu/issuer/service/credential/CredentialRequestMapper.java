package ch.admin.bj.swiyu.issuer.service.credential;

import ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialResponseEncryptionClass;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.ProofType;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.CredentialResponseEncryptionDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.issuance.CreateCredentialRequestDto;
import lombok.experimental.UtilityClass;

import java.text.ParseException;
import java.util.Map;

import static ch.admin.bj.swiyu.issuer.service.SdJwtCredential.SD_JWT_FORMAT;

@UtilityClass
public class CredentialRequestMapper {

    public static CredentialRequestClass toCredentialRequest(CreateCredentialRequestDto dto) {
        return new CredentialRequestClass(
                dto.proofs() == null ? null : Map.of(ProofType.JWT.toString(), dto.proofs().jwt()),
                toCredentialResponseEncryption(dto.credentialResponseEncryption()),
                dto.credentialConfigurationId()
        );
    }

    public static CredentialResponseEncryptionClass toCredentialResponseEncryption(CredentialResponseEncryptionDto credentialRequestDto) {
        if (credentialRequestDto == null) {
            return null;
        }

        try {
            return new CredentialResponseEncryptionClass(
                    credentialRequestDto.jwk(),
                    credentialRequestDto.enc()
            );
        } catch (ParseException e) {
            throw new Oid4vcException(e, CredentialRequestError.INVALID_ENCRYPTION_PARAMETERS, "Encryption JWK cannot be parsed.");
        }
    }
}