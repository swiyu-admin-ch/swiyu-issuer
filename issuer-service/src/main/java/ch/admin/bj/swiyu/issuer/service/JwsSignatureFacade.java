package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.HSMProperties;
import ch.admin.bj.swiyu.issuer.common.config.SignatureConfiguration;
import ch.admin.bj.swiyu.jwssignatureservice.JwsSignatureService;
import ch.admin.bj.swiyu.jwssignatureservice.dto.HSMPropertiesDto;
import ch.admin.bj.swiyu.jwssignatureservice.dto.SignatureConfigurationDto;
import ch.admin.bj.swiyu.jwssignatureservice.factory.strategy.KeyStrategyException;
import com.nimbusds.jose.JWSSigner;
import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
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
     * Create Signer with overridden keyId & keyPin
     */
    @Cacheable(JWS_SIGNER_CACHE)
    public JWSSigner createSigner(@NotNull SignatureConfiguration signatureConfiguration, @Nullable String keyId, @Nullable String keyPin) throws KeyStrategyException {
        SignatureConfigurationDto dto = mapToLibConfig(signatureConfiguration);
        return jwsSignatureService.createSigner(dto, keyId, keyPin);
    }

    private SignatureConfigurationDto mapToLibConfig(SignatureConfiguration cfg) {
        HSMProperties hsm = cfg.getHsm();
        HSMPropertiesDto hsmDto = null;
        if (hsm != null) {
            hsmDto = HSMPropertiesDto.builder()
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

        return SignatureConfigurationDto.builder()
                .keyManagementMethod(cfg.getKeyManagementMethod())
                .privateKey(cfg.getPrivateKey())
                .hsm(hsmDto)
                .pkcs11Config(cfg.getPkcs11Config())
                .verificationMethod(cfg.getVerificationMethod())
                .build();
    }

}