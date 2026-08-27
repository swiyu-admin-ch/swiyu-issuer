package ch.admin.bj.swiyu.issuer.common.config;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

/**
 * Signature configuration that uses a private key directly for signing
 * and does not rely on an HSM or additional signing key configurations.
 *
 * <p>This implementation uses {@code "key"} as its key management method.
 * HSM-related configuration is not supported, and no additional signing
 * keys are maintained.</p>
 */
public class KeyOnlySignatureConfiguration implements SignatureConfiguration {

    @Getter
    @Setter
    private String verificationMethod;

    @Getter
    @Setter
    private String privateKey;

    @Override
    public boolean supportsHSM() {
        return false;
    }

    @Override
    public String getKeyManagementMethod() {
        return "key";
    }

    @Override
    public boolean supportsSigningKeys() {
        return false;
    }

    @Override
    public HSMProperties getHsm() {
        return null;
    }

    @Override
    public String getPkcs11Config() {
        return null;
    }

    @Override
    public List<KeyOnlySignatureConfiguration> getSigningKeys() {
        return List.of();
    }
}
