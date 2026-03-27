package ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest;

import ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import com.nimbusds.jose.jwk.JWK;
import lombok.Data;
import org.springframework.validation.annotation.Validated;

import java.text.ParseException;
import java.util.Map;

@Validated
@Data
public class CredentialResponseEncryptionClass {
    private final Map<String, Object> jwk;
    private final String enc;
    private final JWK parsedJwk;

    public CredentialResponseEncryptionClass(Map<String, Object> jwkJson, String enc) throws ParseException {
        this.jwk = jwkJson;
        this.enc = enc;
        this.parsedJwk = JWK.parse(jwkJson);
        if (parsedJwk.getAlgorithm() == null) {
            throw new Oid4vcException(CredentialRequestError.INVALID_ENCRYPTION_PARAMETERS, "Encryption JWK must have a JWE algorithm specified");
        }
    }

    public String getAlg() {
        return parsedJwk.getAlgorithm().getName();
    }
}