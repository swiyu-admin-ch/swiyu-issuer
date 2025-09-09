package ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding;

import com.nimbusds.jose.jwk.JWK;

@FunctionalInterface
public interface KeyResolver {
    JWK resolveKey(String keyId);
}
