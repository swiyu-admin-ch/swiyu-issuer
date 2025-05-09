package ch.admin.bj.swiyu.issuer.service.factory.strategy;

import ch.admin.bj.swiyu.issuer.common.config.SignatureConfiguration;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.ECKey;
import org.springframework.stereotype.Component;

import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;

/**
 * This strategy is used for the PKCS11 HSM. It requires the key to be created together with a self-signed certificate.
 * The key must be imported into the HSM using the PKCS11 standart.
 */
@Component("pkcs11")
public class PKCS11Strategy implements IKeyManagementStrategy {
    @Override
    public JWSSigner createSigner(SignatureConfiguration signatureConfiguration) throws Exception {
        Provider provider = Security.getProvider("SunPKCS11").configure(signatureConfiguration.getHsm().getPkcs11Config());
        Security.addProvider(provider);
        var hsmKeyStore = KeyStore.getInstance("PKCS11", provider);
        hsmKeyStore.load(null, signatureConfiguration.getHsm().getUserPin().toCharArray());
        var privateKey = ECKey.load(hsmKeyStore, signatureConfiguration.getHsm().getKeyId(), signatureConfiguration.getHsm().getUserPin().toCharArray());

        return fromEC(privateKey, provider);
    }
}