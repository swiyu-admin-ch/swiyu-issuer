package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.SignatureConfiguration;
import ch.admin.bj.swiyu.issuer.service.factory.KeyManagementStrategyFactory;
import ch.admin.bj.swiyu.issuer.service.factory.strategy.KeyStrategyException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSSigner;
import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotNull;
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
    private final ObjectMapper objectMapper;


    /**
     * Create Signer with overridden keyId & keyPin
     */
    @Cacheable(JWS_SIGNER_CACHE)
    public JWSSigner createSigner(@NotNull SignatureConfiguration signatureConfiguration, String keyId, @Nullable String keyPin) throws KeyStrategyException {
        try {
            var config = objectMapper.readValue(objectMapper.writeValueAsString(signatureConfiguration), SignatureConfiguration.class);
            config.getHsm().setKeyId(keyId);
            config.getHsm().setKeyPin(keyPin);
            return buildSigner(config);
        } catch (JsonProcessingException e) {
            throw new KeyStrategyException("Failed to copy signature configuration", e);
        }
    }

    @Cacheable(JWS_SIGNER_CACHE)
    public JWSSigner createSigner(SignatureConfiguration signatureConfiguration) throws KeyStrategyException {
        return buildSigner(signatureConfiguration);
    }

    private JWSSigner buildSigner(SignatureConfiguration signatureConfiguration) throws KeyStrategyException {
        return strategyFactory
                .getStrategy(signatureConfiguration.getKeyManagementMethod())
                .createSigner(signatureConfiguration);
    }
}