package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.SignatureConfiguration;
import ch.admin.bj.swiyu.issuer.service.factory.KeyManagementStrategyFactory;
import ch.admin.bj.swiyu.issuer.service.factory.strategy.KeyStrategy;
import ch.admin.bj.swiyu.issuer.service.factory.strategy.KeyStrategyException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSSigner;
import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import org.apache.commons.lang3.StringUtils;
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
    private final KeyStrategy key;


    /**
     * Create Signer with overridden keyId & keyPin
     */
    @Cacheable(JWS_SIGNER_CACHE)
    public JWSSigner createSigner(@NotNull SignatureConfiguration signatureConfiguration, @Nullable String keyId, @Nullable String keyPin) throws KeyStrategyException {
        try {
            // Deep copy of Signature Configuration, so that we do not override the defaults
            var config = objectMapper.readValue(objectMapper.writeValueAsString(signatureConfiguration), SignatureConfiguration.class);
            if (StringUtils.isNotEmpty(keyId)) {
                config.getHsm().setKeyId(keyId);
            }
            if (StringUtils.isNotEmpty(keyPin)) {
                config.getHsm().setKeyPin(keyPin);
            }
            return buildSigner(config);
        } catch (JsonProcessingException e) {
            throw new KeyStrategyException("Failed to copy signature configuration", e);
        }
    }

    private JWSSigner buildSigner(SignatureConfiguration signatureConfiguration) throws KeyStrategyException {
        return strategyFactory
                .getStrategy(signatureConfiguration.getKeyManagementMethod())
                .createSigner(signatureConfiguration);
    }
}