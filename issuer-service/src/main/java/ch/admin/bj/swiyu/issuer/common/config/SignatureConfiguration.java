package ch.admin.bj.swiyu.issuer.common.config;

import java.util.List;

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
