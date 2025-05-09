package ch.admin.bj.swiyu.issuer.service.factory.strategy;

import ch.admin.bj.swiyu.issuer.common.config.SignatureConfiguration;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.ECKey;
import org.springframework.stereotype.Component;

/**
 * This strategy is used for the ECKey. It requires the key to be created together with a self-signed certificate.
 */
@Component("key")
public class KeyStrategy implements IKeyManagementStrategy {
    @Override
    public JWSSigner createSigner(SignatureConfiguration signatureConfiguration) throws Exception {
        return fromEC(ECKey.parseFromPEMEncodedObjects(signatureConfiguration.getPrivateKey()).toECKey());
    }
}