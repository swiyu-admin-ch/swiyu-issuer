package ch.admin.bj.swiyu.issuer.common.config;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class KeyOnlySignatureConfiguration implements SignatureConfiguration {
    
    private String verificationMethod;

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
