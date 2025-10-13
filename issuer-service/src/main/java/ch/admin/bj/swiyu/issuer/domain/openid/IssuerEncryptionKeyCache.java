package ch.admin.bj.swiyu.issuer.domain.openid;

import com.nimbusds.jose.jwk.JWKSet;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@NoArgsConstructor
public class IssuerEncryptionKeyCache {
    private Map<String, Object> publicEncryptionKeyJWKSetJson;
    private JWKSet secretEncryptionKeyJWKSet;
}
