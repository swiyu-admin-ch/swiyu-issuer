package ch.admin.bj.swiyu.issuer.service.enc;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.CacheConfig;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerCredentialEncryption;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerCredentialRequestEncryption;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerCredentialResponseEncryption;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.jweutil.JweUtil;
import ch.admin.bj.swiyu.jweutil.JweUtilException;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.jwk.JWK;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.apache.commons.lang3.StringUtils;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.text.ParseException;

import static ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError.INVALID_ENCRYPTION_PARAMETERS;

/**
 * Handles encryption-related protocol concerns: publishing supported encryption options
 * and decrypting incoming JWEs using the active key set.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class JweService {

    private final ApplicationProperties applicationProperties;
    private final IssuerMetadata issuerMetadata;
    private final EncryptionKeyService encryptionKeyService;

    /**
     * Overriding bean issuer metadata encryption options with supported values.
     */
    @Transactional(readOnly = true)
    @Cacheable(CacheConfig.ISSUER_METADATA_ENCRYPTION_CACHE)
    public IssuerMetadata issuerMetadataWithEncryptionOptions() {
        IssuerCredentialRequestEncryption requestEncryption = IssuerCredentialRequestEncryption.builder()
                .jwks(encryptionKeyService.getActivePublicKeys())
                .encRequired(applicationProperties.isEncryptionEnforce())
                .build();
        issuerMetadata.setRequestEncryption(requestEncryption);
        issuerMetadata.setResponseEncryption(IssuerCredentialResponseEncryption.builder()
                .encRequired(applicationProperties.isEncryptionEnforce())
                .build());
        return issuerMetadata;
    }

    /**
     * @param encryptedMessage JWE encrypted object serialized as string
     * @return the decrypted object
     * @throws Oid4vcException if the object could not be decrypted
     */
    @Transactional(readOnly = true)
    public String decrypt(String encryptedMessage) {
        try {
            JWEObject encryptedJWT = JWEObject.parse(encryptedMessage);
            JWEHeader header = encryptedJWT.getHeader();
            validateJWEHeaders(header, issuerMetadata.getRequestEncryption());
            JWK key = resolveDecryptionKey(header);
            return JweUtil.decrypt(encryptedMessage, key);
        } catch (ParseException e) {
            throw new Oid4vcException(e, INVALID_ENCRYPTION_PARAMETERS, "Message is not a correct JWE object",
                    Map.of("payloadLength", encryptedMessage != null ? encryptedMessage.length() : 0));
        } catch (JweUtilException e) {
            throw new Oid4vcException(e, INVALID_ENCRYPTION_PARAMETERS, "JWE Object could not be decrypted",
                    Map.of("payloadLength", encryptedMessage != null ? encryptedMessage.length() : 0));
        }
    }

    /**
     * @return true, if credential requests MUST be encrypted
     */
    public boolean isRequestEncryptionMandatory() {
        IssuerCredentialRequestEncryption encryptionOptions = issuerMetadata.getRequestEncryption();
        return encryptionOptions != null && encryptionOptions.isEncRequired();
    }


    /**
     * Decrypts the message if the content type indicates it is a JWE.
     * If the content type is not JWE and encryption is mandatory, an exception is thrown.
     * Otherwise, the original message is returned.
     *
     * @param requestMessage the message to be decrypted
     * @param contentType    the content type of the message
     * @return decrypted message or original message
     */
    public String decryptRequest(String requestMessage, String contentType) {
        // Decrypt if holder sent an encrypted
        if (StringUtils.equalsIgnoreCase("application/jwt", contentType)) {
            return decrypt(requestMessage);
        } else if (isRequestEncryptionMandatory()) {
            throw new Oid4vcException(INVALID_ENCRYPTION_PARAMETERS,
                    "Request encryption is mandatory with content type set to application/jwt",
                    Map.of("contentType", contentType != null ? contentType : "null"));
        }
        return requestMessage;
    }

    /**
     * ensures the JWEHeader uses the properties required in the issuer metadata
     *
     * @param header         header to be validated
     * @param encryptionSpec Credential encryption spec published in the issuer metadata
     */
    private void validateJWEHeaders(JWEHeader header, IssuerCredentialEncryption encryptionSpec) {
        if (encryptionSpec == null) {
            throw new Oid4vcException(INVALID_ENCRYPTION_PARAMETERS, "Encryption not supported by issuer metadata",
                    Map.of("headerAlg", header.getAlgorithm() != null ? header.getAlgorithm().getName() : "null",
                            "headerEnc", header.getEncryptionMethod() != null ? header.getEncryptionMethod().toString() : "null"));
        }
        checkEncryptionMethodSupported(header, encryptionSpec);
        checkCompressionMethodSupported(header, encryptionSpec);
    }

    /**
     * Checks if the encryption method in the JWE header is supported by the issuer metadata.
     * Throws Oid4vcException if not supported.
     */
    private void checkEncryptionMethodSupported(JWEHeader header, IssuerCredentialEncryption encryptionSpec) {
        if (header.getEncryptionMethod() == null || !encryptionSpec.getEncValuesSupported().contains(header.getEncryptionMethod().toString())) {
            throw new Oid4vcException(INVALID_ENCRYPTION_PARAMETERS,
                    "Unsupported encryption method. Must be one of %s but was %s".formatted(encryptionSpec.getEncValuesSupported(),
                            header.getEncryptionMethod()),
                    Map.of(
                            "supportedEncs", encryptionSpec.getEncValuesSupported(),
                            "headerEnc", header.getEncryptionMethod() != null ? header.getEncryptionMethod().toString() : "null"
                    ));
        }
    }

    /**
     * Checks if the compression (zip) method in the JWE header is supported by the issuer metadata.
     * Throws Oid4vcException if not supported.
     */
    private void checkCompressionMethodSupported(JWEHeader header, IssuerCredentialEncryption encryptionSpec) {
        var supportedZips = encryptionSpec.getZipValuesSupported();
        var headerZip = header.getCompressionAlgorithm();
        if (supportedZips != null && (headerZip == null || !supportedZips.contains(headerZip.toString()))) {
            throw new Oid4vcException(INVALID_ENCRYPTION_PARAMETERS,
                    "Unsupported compression (zip) method. Must be one of %s but was %s".formatted(supportedZips, headerZip),
                    Map.of(
                            "supportedZips", supportedZips,
                            "headerZip", headerZip != null ? headerZip.toString() : "null"
                    ));
        }
    }

    /**
     * Resolves a private key for the JWE header and validates the algorithm family.
     *
     * @param header JWEHeader holding key information
     * @return the JWK to use for decryption
     * @throws Oid4vcException if an unknown key or unsupported algorithm was used in the JWEHeader
     */
    private JWK resolveDecryptionKey(JWEHeader header) {
        JWK key = encryptionKeyService.getActivePrivateKeys().getKeyByKeyId(header.getKeyID());
        if (key == null) {
            var kid = header.getKeyID();
            throw new Oid4vcException(INVALID_ENCRYPTION_PARAMETERS, "Unknown JWK Key Id: " + header.getKeyID(),
                    Map.of(
                            "kidPresent", kid != null,
                            "kidLength", kid != null ? kid.length() : 0
                    ));
        }
        if (!JWEAlgorithm.Family.ECDH_ES.contains(header.getAlgorithm())) {
            throw new Oid4vcException(INVALID_ENCRYPTION_PARAMETERS, "Unsupported Encryption Algorithm");
        }

        return key;
    }

}
