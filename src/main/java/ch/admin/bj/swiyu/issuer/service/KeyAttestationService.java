package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.AttestationJwt;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.KeyResolver;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.KeyAttestationRequirement;
import com.nimbusds.jose.JOSEException;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.text.ParseException;

import static ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError.INVALID_PROOF;

@Service
@AllArgsConstructor
public class KeyAttestationService {
    private final KeyResolver keyResolver;

    public boolean isValidKeyAttestation(@NotNull KeyAttestationRequirement attestationRequirement, @NotNull String attestationJwt) {
        try {
            return AttestationJwt.parseJwt(attestationJwt).isValidAttestation(keyResolver, attestationRequirement.getKeyStorage());
        } catch (ParseException e) {
            throw new Oid4vcException(e, INVALID_PROOF, "Attestation is malformed!");
        } catch (IllegalArgumentException e) {
            throw new Oid4vcException(e, INVALID_PROOF, String.format("Attestation is malformed! %s", e.getMessage()));
        } catch (JOSEException e) {
            throw new Oid4vcException(e, INVALID_PROOF, "Attestation key is not supported or not matching the signature!");
        }

    }

}
