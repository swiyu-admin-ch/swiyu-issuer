package ch.admin.bj.swiyu.issuer.service.factory.strategy;

import ch.admin.bj.swiyu.issuer.common.config.SignatureConfiguration;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.JWK;
import org.springframework.stereotype.Component;

/**
 * This strategy is used for the ECKey. It requires the key to be created together with a self-signed certificate.
 */
@Component("key")
public class KeyStrategy implements IKeyManagementStrategy {
    @Override
    public JWSSigner createSigner(SignatureConfiguration signatureConfiguration) throws KeyStrategyException {
        try {
            return fromEC(JWK.parseFromPEMEncodedObjects(signatureConfiguration.getPrivateKey()).toECKey());
        } catch (JOSEException e) {
            throw new KeyStrategyException("Failed to parse EC Key from PEM.", e);
        }
    }
}