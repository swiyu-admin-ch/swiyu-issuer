package ch.admin.bj.swiyu.issuer.common.config;

import java.util.List;

/**
 * Defines the configuration required for signature generation and verification.
 *
 * <p>The configuration can describe either an HSM-based signing setup,
 * directly configured signing keys, or both. It also provides the
 * verification method used to validate signatures.</p>
 */
public interface SignatureConfiguration {
    boolean supportsHSM();

    boolean supportsSigningKeys();

    String getKeyManagementMethod();

    String getPrivateKey();

    void setPrivateKey(String privateKey);

    HSMProperties getHsm();

    String getPkcs11Config();

    String getVerificationMethod();

    void setVerificationMethod(String verificationMethod);

    List<KeyOnlySignatureConfiguration> getSigningKeys();
}
