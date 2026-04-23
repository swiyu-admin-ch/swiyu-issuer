package ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding;

import com.nimbusds.jose.jwk.JWK;

import java.text.ParseException;

/**
 * Container for wallet holder keys used in holder bindings
 */
public record HolderKeyBinding(String holderKeyJson) {

    public JWK getJWK() throws ParseException {
        return JWK.parse(holderKeyJson);
    }
}
