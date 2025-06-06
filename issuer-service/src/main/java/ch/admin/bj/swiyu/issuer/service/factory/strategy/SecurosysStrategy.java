package ch.admin.bj.swiyu.issuer.service.factory.strategy;

import ch.admin.bj.swiyu.issuer.common.config.SignatureConfiguration;
import com.nimbusds.jose.JWSSigner;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;

/**
 * This strategy is used for the Securosys HSM. It requires the key to be created together with a self-signed certificate.
 * The connection to the HSM is made through Primus JCA/JCE.
 * The key must be created in or imported into the HSM using the Primus tools.
 * <p>
 * See https://docs.securosys.com/primus-tools/Use-Cases/certificate-sign-request
 */
@Component("securosys")
public class SecurosysStrategy implements IKeyManagementStrategy {
    @Override
    public JWSSigner createSigner(SignatureConfiguration signatureConfiguration) throws Exception {
        // Inspired by https://docs.securosys.com/assets/files/ProxyConfigSample-1a86820104d8ada67f90d5218f2db5f8.java
        // Requires the key to be created together with a self-signed certificate as described in https://docs.securosys.com/primus-tools/Use-Cases/certificate-sign-request
        // Dynamic Imported Primus
        final var baos = new ByteArrayOutputStream();
        // Create ad-hoc configuration
        (new PrintStream(baos)).println(
                signatureConfiguration.getHsm().getSecurosysStringConfig()
        );
        final var bais = new ByteArrayInputStream(baos.toByteArray());
        final var provider = (Provider) Class.forName("com.securosys.primus.jce.PrimusProvider").getDeclaredConstructor().newInstance();

        Security.addProvider(provider);
        var hsmKeyStore = KeyStore.getInstance("Primus");
        hsmKeyStore.load(bais, null);

        // Loading the ECKey does not work for securosys provider, it does things different than expected by nimbus
        var privateKey = (ECPrivateKey) hsmKeyStore.getKey(signatureConfiguration.getHsm().getKeyId(), signatureConfiguration.getHsm().getUserPin().toCharArray());
        return fromEC(privateKey, provider);
    }
}