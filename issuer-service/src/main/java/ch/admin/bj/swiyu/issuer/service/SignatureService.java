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
 * This service is used to create a signer for the given signature configuration.
 * It uses the KeyManagementStrategyFactory to create the signer based on the key management method.
 * <p>
 * The signer is cached to avoid creating it multiple times.
 */
@Service
@AllArgsConstructor
public class SignatureService {

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