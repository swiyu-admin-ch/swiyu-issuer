package ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest;

import ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.nimbusds.jose.jwk.JWK;
import lombok.Data;

import org.springframework.validation.annotation.Validated;

import java.text.ParseException;
import java.util.Map;

@Validated
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class CredentialResponseEncryptionClass {
    private  Map<String, Object> jwk;
    private  String enc;

    public CredentialResponseEncryptionClass(Map<String, Object> jwkJson, String enc) {
        this.jwk = jwkJson;
        this.enc = enc;
    }
    
    /**
     * Gets the encryption algorithm from the enclosed Json Web Key
     * @return the encryption key algorithm as string
     */
    @JsonIgnore
    public String extractAlg() {
        try {
        var parsedJwk = JWK.parse(this.jwk);
        if (parsedJwk.getAlgorithm() == null) {
            throw new Oid4vcException(CredentialRequestError.INVALID_ENCRYPTION_PARAMETERS, "Encryption JWK must have a JWE algorithm specified");
        }
        return parsedJwk.getAlgorithm().getName();
        } catch (ParseException e) {
            throw new Oid4vcException(e, CredentialRequestError.INVALID_ENCRYPTION_PARAMETERS, "Encryption JWK cannot be parsed.");
        }
    }
}