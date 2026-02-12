package ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest;

import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.validation.annotation.Validated;

import java.util.Map;

@Validated
@Data
@AllArgsConstructor
public class CredentialResponseEncryptionClass {
    private Map<String, Object> jwk;
    private String alg;
    private String enc;
}