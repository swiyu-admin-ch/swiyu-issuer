/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.test;

import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.AttackPotentialResistance;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.DidJwk;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.time.Instant;
import java.util.Date;
import java.util.List;

public class TestServiceUtils {

    public static String createHolderProof(ECKey holderPrivateKey, String issuerUri, String nonce, String proofTypeString, boolean useDidJwk) throws JOSEException {
        return createHolderProof(holderPrivateKey, issuerUri, nonce, proofTypeString, useDidJwk, new Date());
    }

    public static String createAttestedHolderProof(ECKey holderPrivateKey, String issuerUri, String nonce, String proofTypeString, boolean useDidJwk, AttackPotentialResistance attestationLevel, String attestationIssuerDid) throws JOSEException {
        return createHolderproofJWT(holderPrivateKey, issuerUri, nonce, proofTypeString, useDidJwk, new Date(), attestationLevel, attestationIssuerDid);
    }

    public static String createHolderProof(ECKey holderPrivateKey, String issuerUri, String nonce, String proofTypeString, boolean useDidJwk, Date issueTime) throws JOSEException {
        return createHolderproofJWT(holderPrivateKey, issuerUri, nonce, proofTypeString, useDidJwk, issueTime, null, null);
    }

    @NotNull
    private static String createHolderproofJWT(ECKey holderPrivateKey, String issuerUri, String nonce, String proofTypeString, boolean useDidJwk, Date issueTime, @Nullable AttackPotentialResistance attestationLevel, @Nullable String attestationIssuerDid) throws JOSEException {
        JWSSigner signer = new ECDSASigner(holderPrivateKey);

        var headerBuilder = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType(proofTypeString));
        if (useDidJwk) {
            headerBuilder.keyID(DidJwk.createFromJsonString(holderPrivateKey.toPublicJWK().toJSONString()).getDidJwk());
        } else {
            headerBuilder.jwk(holderPrivateKey.toPublicJWK());
        }
        // Add attestation if required
        if (attestationLevel != null) {
            var attestation = createKeyAttestation(attestationLevel, holderPrivateKey.toPublicJWK(), attestationIssuerDid == null ? "did:test:test-attestation-builder" : attestationIssuerDid);
            attestation.sign(signer);
            headerBuilder.customParam("key_attestation", attestation.serialize());
        }
        JWSHeader header = headerBuilder
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .claim("nonce", nonce)
                .claim("aud", issuerUri)
                .issueTime(issueTime)
                .build();

        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(signer);
        return jwt.serialize();
    }

    private static SignedJWT createKeyAttestation(AttackPotentialResistance attestationLevel, ECKey publicJWK, String attestationIssuerDid) {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("key-attestation+jwt"))
                .keyID(attestationIssuerDid + "#key-1")
                .build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(attestationIssuerDid)
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .claim("key_storage", List.of(attestationLevel.getValue()))
                .claim("attested_keys", List.of(publicJWK.toJSONObject()))
                .build();
        return new SignedJWT(header, claims);
    }

}