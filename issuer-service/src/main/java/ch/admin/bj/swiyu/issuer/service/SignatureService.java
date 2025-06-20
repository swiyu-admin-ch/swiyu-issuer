package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.SignatureConfiguration;
import ch.admin.bj.swiyu.issuer.service.factory.KeyManagementStrategyFactory;
import com.nimbusds.jose.JWSSigner;
import lombok.AllArgsConstructor;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import static ch.admin.bj.swiyu.issuer.common.config.CacheConfig.JWS_SIGNER_CACHE;

/**
 * This service is used to create a signer for the given signature configuration.
 * It uses the KeyManagementStrategyFactory to create the signer based on the key management method.
 * <p>
 * The signer is cached to avoid creating it multiple times.
 */
@Service
@AllArgsConstructor
public class SignatureService {

    private final KeyManagementStrategyFactory strategyFactory;

    @Cacheable(JWS_SIGNER_CACHE)
    public JWSSigner defaultSigner(SignatureConfiguration signatureConfiguration) throws Exception {
        return strategyFactory
                .getStrategy(signatureConfiguration.getKeyManagementMethod())
                .createSigner(signatureConfiguration);
    }
}