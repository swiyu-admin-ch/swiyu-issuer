package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.HSMProperties;
import ch.admin.bj.swiyu.issuer.common.config.SignatureConfiguration;
import ch.admin.bj.swiyu.issuer.common.exception.ConfigurationException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.ConfigurationOverride;
import ch.admin.bj.swiyu.jwssignatureservice.JwsSignatureService;
import ch.admin.bj.swiyu.jwssignatureservice.dto.HSMPropertiesDto;
import ch.admin.bj.swiyu.jwssignatureservice.dto.SignatureConfigurationDto;
import ch.admin.bj.swiyu.jwssignatureservice.factory.strategy.KeyStrategyException;
import com.nimbusds.jose.JWSSigner;
import lombok.AllArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import static ch.admin.bj.swiyu.issuer.common.config.CacheConfig.JWS_SIGNER_CACHE;

/**
 * Facade service for creating {@link JWSSigner} instances using the {@link JwsSignatureService}.
 * <p>
 * This class provides a simplified interface to create signers for given signature configurations,
 * supporting both software and HSM-based key management. Signers are cached to optimize performance.
 * <p>
 * Instances of this class should be created via dependency injection (e.g., by Spring),
 * as it requires a {@link JwsSignatureService} dependency.
 */
@Service
@AllArgsConstructor
public class JwsSignatureFacade {

    private final JwsSignatureService jwsSignatureService;


    /**
     * Creates a JWS signer with optional configuration overrides.
     *
     * @param signatureConfiguration the base signature configuration
     * @param override               the configuration override (keyId, keyPin, verificationMethod)
     * @return a configured JWS signer instance
     * @throws KeyStrategyException   if signer creation fails
     * @throws ConfigurationException if the configuration is invalid or verification method not found
     */
    @Cacheable(JWS_SIGNER_CACHE)
    public JWSSigner createSigner(SignatureConfiguration signatureConfiguration, ConfigurationOverride override)
            throws KeyStrategyException {

        validateInputs(signatureConfiguration, override);

        SignatureConfiguration resolvedConfig = resolveConfiguration(signatureConfiguration, override);
        SignatureConfigurationDto dto = mapToDto(resolvedConfig);

        return jwsSignatureService.createSigner(dto, override.keyId(), override.keyPin());
    }

    private SignatureConfiguration resolveConfiguration(SignatureConfiguration baseConfig, ConfigurationOverride override) {
        if (StringUtils.isEmpty(override.verificationMethod())) {
            return baseConfig;
        }

        if (baseConfig.getVerificationMethod().equals(override.verificationMethod()) || (baseConfig.supportsHSM() && override.keyId() != null)) {
            return baseConfig;
        }

        // if hsm set use hsm
        if (baseConfig.supportsHSM() && override.keyId() != null) {
            return baseConfig;
        }

        return findMatchingSigningKey(baseConfig, override.verificationMethod());
    }

    private SignatureConfiguration findMatchingSigningKey(SignatureConfiguration baseConfig, String verificationMethod) {
        if (!baseConfig.supportsSigningKeys()) {
            throw new ConfigurationException("No signing key found for verification method: " + verificationMethod);
        }

        return baseConfig.getSigningKeys().stream()
                .filter(key -> key.getVerificationMethod().equals(verificationMethod))
                .findFirst()
                .orElseThrow(() -> new ConfigurationException("No signing key found for verification method: " + verificationMethod));
    }

    private void validateInputs(SignatureConfiguration signatureConfiguration, ConfigurationOverride override) {
        if (signatureConfiguration == null) {
            throw new ConfigurationException("Signature configuration cannot be null.");
        }

        if (override == null) {
            throw new ConfigurationException("Configuration override cannot be null.");
        }

        if (signatureConfiguration.supportsHSM() && StringUtils.isEmpty(override.keyId())) {
            throw new ConfigurationException("Key ID override is not supported for HSM configurations.");
        }
    }

    private HSMPropertiesDto mapHsmProperties(HSMProperties hsm) {
        if (hsm == null) {
            return null;
        }

        return HSMPropertiesDto.builder()
                .userPin(hsm.getUserPin())
                .keyId(hsm.getKeyId())
                .keyPin(hsm.getKeyPin())
                .pkcs11Config(hsm.getPkcs11Config())
                .user(hsm.getUser())
                .host(hsm.getHost())
                .port(hsm.getPort())
                .password(hsm.getPassword())
                .proxyUser(hsm.getProxyUser())
                .proxyPassword(hsm.getProxyPassword())
                .build();
    }

    private SignatureConfigurationDto mapToDto(SignatureConfiguration config) {
        return SignatureConfigurationDto.builder()
                .keyManagementMethod(config.getKeyManagementMethod())
                .privateKey(config.getPrivateKey())
                .hsm(mapHsmProperties(config.getHsm()))
                .pkcs11Config(config.getPkcs11Config())
                .verificationMethod(config.getVerificationMethod())
                .build();
    }
}