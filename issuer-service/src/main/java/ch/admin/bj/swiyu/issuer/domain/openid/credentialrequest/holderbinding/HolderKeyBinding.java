package ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding;

import com.nimbusds.jose.jwk.JWK;

import java.text.ParseException;

/**
 * Converter from did jwk to jwk and back
 */
public record HolderKeyBinding(String holderKeyJson) {

    public static HolderKeyBinding createFromJsonString(String jwkJsonString) {
        return new HolderKeyBinding(jwkJsonString);
    }

    public JWK getJWK() throws ParseException {
        return JWK.parse(holderKeyJson);
    }
}
