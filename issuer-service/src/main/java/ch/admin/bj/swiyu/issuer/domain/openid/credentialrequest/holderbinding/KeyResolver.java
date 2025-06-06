package ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding;

import com.nimbusds.jose.jwk.JWK;

public interface KeyResolver {
    JWK resolveKey(String keyId);
}
