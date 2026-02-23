package ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.encryption;

import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialResponseEncryptionClass;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerCredentialResponseEncryption;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import jakarta.annotation.Nullable;

import java.util.Map;
import java.text.ParseException;

import static ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError.INVALID_ENCRYPTION_PARAMETERS;

public class CredentialResponseEncryptor {
    @Nullable
    private final IssuerCredentialResponseEncryption offeredEncryption;
    @Nullable
    private final CredentialResponseEncryptionClass requestedEncryption;


    public CredentialResponseEncryptor(@Nullable IssuerCredentialResponseEncryption offeredEncryption, @Nullable CredentialResponseEncryptionClass requestedEncryption) {
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
            throw new Oid4vcException(INVALID_ENCRYPTION_PARAMETERS,
                    "Encryption was requested but is not offered.",
                    Map.of(
                            "requestedAlg", requestedEncryption.getAlg(),
                            "requestedEnc", requestedEncryption.getEnc()
                    ));
        }
        // Encryption optional and not requested
        else if (!offeredEncryption.isEncRequired() && requestedEncryption == null) {
            return false;
        }
        // Encryption required but not requested
        else if (offeredEncryption.isEncRequired() && requestedEncryption == null) {
            throw new Oid4vcException(INVALID_ENCRYPTION_PARAMETERS,
                    "Credential Response Encryption is mandatory.",
                    Map.of("encRequired", true));
        }
        // Requested encryption method not offered
        else if (!offeredEncryption.contains(requestedEncryption)) {
            throw new Oid4vcException(
                    INVALID_ENCRYPTION_PARAMETERS,
                    String.format("Requested encryption is not offered. alg: %s , enc: %s",
                            requestedEncryption.getAlg(), requestedEncryption.getEnc()),
                    Map.of(
                            "requestedAlg", requestedEncryption.getAlg(),
                            "requestedEnc", requestedEncryption.getEnc(),
                            "offeredAlgs", offeredEncryption.getAlgValuesSupported(),
                            "offeredEncs", offeredEncryption.getEncValuesSupported()
                    ));
        }
        // Encryption is to be done
        return true;
    }

    private JWK guardedParseJWK() {
        try {
            return JWK.parse(requestedEncryption.getJwk());
        } catch (ParseException e) {
            var jwk = requestedEncryption.getJwk();
            throw new Oid4vcException(e, INVALID_ENCRYPTION_PARAMETERS,
                    "Could not parse provided JWK.",
                    Map.of(
                            "jwkPresent", jwk != null
                    ));
        }
    }

    private JWEEncrypter guardedCreateEncrypter(JWK key) {
        try {
            KeyType keyType = key.getKeyType();
            if (keyType == KeyType.EC) {
                return new ECDHEncrypter(key.toECKey().toECPublicKey());
            } else {
                throw new Oid4vcException(INVALID_ENCRYPTION_PARAMETERS,
                        "Unsupported kty " + keyType.getValue(),
                        Map.of("kty", keyType.getValue()));
            }
        } catch (JOSEException e) {
            throw new Oid4vcException(e,
                    INVALID_ENCRYPTION_PARAMETERS,
                    "Mismatch between specified encryption algorithm, encryption & provided key - " + e.getMessage(),
                    Map.of(
                            "alg", requestedEncryption != null ? requestedEncryption.getAlg() : "null",
                            "enc", requestedEncryption != null ? requestedEncryption.getEnc() : "null"
                    )
            );
        }
    }


    public String encryptResponse(String oid4vciCredentialJson) {
        JWEAlgorithm alg = JWEAlgorithm.parse(requestedEncryption.getAlg());
        EncryptionMethod enc = EncryptionMethod.parse(requestedEncryption.getEnc());
        JWK holderPublicKey = guardedParseJWK();


        JWEHeader header = new JWEHeader.Builder(alg, enc).compressionAlgorithm(CompressionAlgorithm.DEF).build();
        Payload payload = new Payload(oid4vciCredentialJson);
        JWEObject jwe = new JWEObject(header, payload);
        JWEEncrypter encryptor = guardedCreateEncrypter(holderPublicKey);
        return encrypt(jwe, encryptor);

    }

    private String encrypt(JWEObject jwe, JWEEncrypter encryptor) {
        try {
            jwe.encrypt(encryptor);
            return jwe.serialize();
        } catch (JOSEException e) {
            throw new Oid4vcException(e, INVALID_ENCRYPTION_PARAMETERS,
                    "Encryption was not possible with the provided parameters - " + e.getMessage(),
                    Map.of(
                            "alg", requestedEncryption != null ? requestedEncryption.getAlg() : "null",
                            "enc", requestedEncryption != null ? requestedEncryption.getEnc() : "null"
                    )
            );
        }
    }
}
