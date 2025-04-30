/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.credentialrequest.encryption;

import ch.admin.bj.swiyu.issuer.oid4vci.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.credentialrequest.CredentialResponseEncryption;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.metadata.IssuerCredentialResponseEncryption;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import jakarta.annotation.Nullable;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;

import static ch.admin.bj.swiyu.issuer.oid4vci.common.exception.CredentialRequestError.INVALID_ENCRYPTION_PARAMETERS;

public class CredentialResponseEncryptor {
    @Nullable
    private final IssuerCredentialResponseEncryption offeredEncryption;
    @Nullable
    private final CredentialResponseEncryption requestedEncryption;


    public CredentialResponseEncryptor(@Nullable IssuerCredentialResponseEncryption offeredEncryption, @Nullable CredentialResponseEncryption requestedEncryption) {
        this.offeredEncryption = offeredEncryption;
        this.requestedEncryption = requestedEncryption;
    }

    /**
     * Evaluates if an encryption is required
     *
     * @throws Oid4vcException if an invalid offeredEncryption & requestedEncryption combination is provided
     */
    public boolean isEncryptionRequired() {
        // Nobody interested in encryption
        if (offeredEncryption == null && requestedEncryption == null) {
            return false;
        }
        // No offered encryption, but requested
        else if (offeredEncryption == null) {
            throw new Oid4vcException(INVALID_ENCRYPTION_PARAMETERS, "Encryption was requested but is not offered.");
        }
        // Encryption optional and not requested
        else if (!offeredEncryption.isEncRequired() && requestedEncryption == null) {
            return false;
        }
        // Encryption required but not requested
        else if (offeredEncryption.isEncRequired() && requestedEncryption == null) {
            throw new Oid4vcException(INVALID_ENCRYPTION_PARAMETERS, "Credential Response Encryption is mandatory.");
        }
        // Requested encryption method not offered
        else if (!offeredEncryption.contains(requestedEncryption)) {
            throw new Oid4vcException(
                    INVALID_ENCRYPTION_PARAMETERS,
                    String.format("Requested encryption is not offered. alg: %s , enc: %s",
                            requestedEncryption.getAlg(), requestedEncryption.getEnc()));
        }
        // Encryption is to be done
        return true;
    }

    private JWK guardedParseJWK() {
        try {
            return JWK.parse(requestedEncryption.getJwk());
        } catch (ParseException e) {
            throw new Oid4vcException(e, INVALID_ENCRYPTION_PARAMETERS, "Could not parse provided JWK.");
        }
    }

    private SecretKey guardedGenerateSymmetricKey(EncryptionMethod enc) {
        SecretKey symmetricKey;
        try {
            KeyGenerator symmetricKeyGenerator = KeyGenerator.getInstance("AES");
            symmetricKeyGenerator.init(enc.cekBitLength());
            symmetricKey = symmetricKeyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new Oid4vcException(e, INVALID_ENCRYPTION_PARAMETERS, "No Key generator found algorithm");
        }
        return symmetricKey;
    }

    private JWEEncrypter guardedCreateEncrypter(JWK key, SecretKey cek) {
        try {
            KeyType keyType = key.getKeyType();
            if (keyType == KeyType.RSA) {
                return new RSAEncrypter(key.toRSAKey().toRSAPublicKey(), cek);
            } else if (keyType == KeyType.EC) {
                return new ECDHEncrypter(key.toECKey().toECPublicKey(), cek);
            } else {
                throw new Oid4vcException(INVALID_ENCRYPTION_PARAMETERS, "Unsupported kty " + keyType.getValue());
            }
        } catch (JOSEException e) {
            throw new Oid4vcException(e,
                    INVALID_ENCRYPTION_PARAMETERS,
                    "Mismatch between specified encryption algorithm, encryption & provided key - " + e.getMessage()
            );
        }
    }


    public String encryptResponse(String oid4vciCredentialJson) {
        JWEAlgorithm alg = JWEAlgorithm.parse(requestedEncryption.getAlg());
        EncryptionMethod enc = EncryptionMethod.parse(requestedEncryption.getEnc());
        JWK holderPublicKey = guardedParseJWK();
        SecretKey cek = guardedGenerateSymmetricKey(enc);


        JWEHeader header = new JWEHeader(alg, enc);
        Payload payload = new Payload(oid4vciCredentialJson);
        JWEObject jwe = new JWEObject(header, payload);
        JWEEncrypter encryptor = guardedCreateEncrypter(holderPublicKey, cek);
        return encrypt(jwe, encryptor);

    }

    private String encrypt(JWEObject jwe, JWEEncrypter encryptor) {
        try {
            jwe.encrypt(encryptor);
            return jwe.serialize();
        } catch (JOSEException e) {
            throw new Oid4vcException(e, INVALID_ENCRYPTION_PARAMETERS,
                    "Encryption was not possible with the provided parameters - " + e.getMessage()
            );
        }
    }
}
