/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding;

import com.nimbusds.jose.jwk.JWK;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Base64;

/**
 * Converter from did jwk to jwk and back
 */
public class DidJwk {
    private final String holderKeyJson;

    public DidJwk(String holderKeyJson) {
        this.holderKeyJson = holderKeyJson;
    }

    public static DidJwk createFromDidJwk(String didJwk) {
        var didParts = didJwk.split(":");
        return new DidJwk(decode(didParts[didParts.length - 1]));
    }

    public static DidJwk createFromJsonString(String jwkJsonString) {
        return new DidJwk(jwkJsonString);
    }

    public JWK getJWK() throws ParseException {
        return JWK.parse(holderKeyJson);
    }

    public String getDidJwk() {
        return String.format("did:jwk:%s", encode(holderKeyJson));
    }

    private static String encode(String jsonString) {
        return Base64
                .getUrlEncoder()
                .withoutPadding()
                .encodeToString(jsonString.getBytes(StandardCharsets.UTF_8));
    }

    private static String decode(String base64String) {
        return new String(Base64.getUrlDecoder().decode(base64String));
    }
}
