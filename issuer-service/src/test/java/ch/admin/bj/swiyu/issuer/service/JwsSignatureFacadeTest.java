package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.HSMProperties;
import ch.admin.bj.swiyu.issuer.common.config.KeyOnlySignatureConfiguration;
import ch.admin.bj.swiyu.issuer.common.config.SignatureConfigurationWithHsm;
import ch.admin.bj.swiyu.issuer.common.exception.ConfigurationException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.ConfigurationOverride;
import ch.admin.bj.swiyu.jwssignatureservice.JwsSignatureService;
import ch.admin.bj.swiyu.jwssignatureservice.dto.HSMPropertiesDto;
import ch.admin.bj.swiyu.jwssignatureservice.dto.SignatureConfigurationDto;
import com.nimbusds.jose.JWSSigner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class JwsSignatureFacadeTest {

    private final String baseConfig = "did:example:issuer";
    private final String baseConfigKeyId = baseConfig + "#key-1";

    private JwsSignatureService jwsSignatureService;
    private JwsSignatureFacade facade;

    @BeforeEach
    void setUp() {
        jwsSignatureService = mock(JwsSignatureService.class);
        facade = new JwsSignatureFacade(jwsSignatureService);
    }

    @Test
    void createSigner_withDefaultKey_andSameOverride_thenSuccess() throws Exception {
        SignatureConfigurationWithHsm cfg = baseConfiguration(baseConfigKeyId);

        ConfigurationOverride override = new ConfigurationOverride(baseConfig, baseConfigKeyId, null, null);
        assertDoesNotThrow(() -> facade.createSigner(cfg, override));

        verify(jwsSignatureService, times(1)).createSigner(any(SignatureConfigurationDto.class), isNull(), isNull());
    }

    @Test
    void createSigner_withoutKeyOverride_mapsConfigurationAndDelegates() throws Exception {
        SignatureConfigurationWithHsm cfg = baseConfiguration(baseConfigKeyId);
        JWSSigner signer = mock(JWSSigner.class);

        when(jwsSignatureService.createSigner(any(SignatureConfigurationDto.class), isNull(), isNull())).thenReturn(signer);

        ConfigurationOverride override = new ConfigurationOverride(null, null, null, null);
        JWSSigner result = facade.createSigner(cfg, override);

        assertSame(signer, result);
        ArgumentCaptor<SignatureConfigurationDto> captor = ArgumentCaptor.forClass(SignatureConfigurationDto.class);

        verify(jwsSignatureService).createSigner(captor.capture(), isNull(), isNull());

        assertThat(captor.getValue()).usingRecursiveComparison().isEqualTo(
                SignatureConfigurationDto.builder()
                        .keyManagementMethod("key")
                        .privateKey("private-key")
                        .hsm(null)
                        .verificationMethod(baseConfigKeyId)
                        .build()
        );
    }

    @Test
    void createSigner_withValidOnlyKeyId_noOverride_thenSuccess() throws Exception {
        SignatureConfigurationWithHsm cfg = baseConfiguration(baseConfigKeyId);

        ConfigurationOverride override = new ConfigurationOverride(null, null, null, null);
        assertDoesNotThrow(() -> facade.createSigner(cfg, override));

        verify(jwsSignatureService, times(1)).createSigner(any(SignatureConfigurationDto.class), any(), any());
    }


    @Test
    void createSigner_withUnknownKeyIdOverride_noHSM_noSigningKeys_throwsConfigurationException() throws Exception {
        SignatureConfigurationWithHsm cfg = baseConfiguration(baseConfigKeyId);
        var differentKeyId = baseConfigKeyId + "different-key";

        ConfigurationOverride override = new ConfigurationOverride(baseConfig, differentKeyId, null, null);
        assertThrows(ConfigurationException.class, () -> facade.createSigner(cfg, override));

        verify(jwsSignatureService, never()).createSigner(any(SignatureConfigurationDto.class), any(), any());
    }

    @Test
    void createSigner_withUnknownKeyIdOverride_noHSM_validSigningKeys_thenSuccess() throws Exception {
        SignatureConfigurationWithHsm cfg = baseConfiguration(baseConfigKeyId);
        var differentKeyId = baseConfigKeyId + "different-key";

        cfg.setSigningKeys(List.of(keySignatureConfiguration(differentKeyId)));

        ConfigurationOverride override = new ConfigurationOverride(null, null, null, null);
        assertDoesNotThrow(() -> facade.createSigner(cfg, override));

        verify(jwsSignatureService, times(1)).createSigner(any(SignatureConfigurationDto.class), any(), any());
    }

    @Test
    void createSigner_withUnknownKeyIdOverride_withHSM_noValidSigningKeys_thenSuccess() throws Exception {
        SignatureConfigurationWithHsm cfg = baseConfiguration(baseConfigKeyId);
        var differentKeyId = baseConfigKeyId + "different-key";
        var pin = "pin";
        cfg.setHsm(hsmProperties(differentKeyId));
        cfg.setSigningKeys(List.of(keySignatureConfiguration(baseConfigKeyId)));

        ConfigurationOverride override = new ConfigurationOverride(null, null, differentKeyId, pin);
        assertDoesNotThrow(() -> facade.createSigner(cfg, override));

        ArgumentCaptor<SignatureConfigurationDto> captor = ArgumentCaptor.forClass(SignatureConfigurationDto.class);
        verify(jwsSignatureService).createSigner(captor.capture(), eq(differentKeyId), eq(pin));
        assertThat(captor.getValue()).usingRecursiveComparison().isEqualTo(
                SignatureConfigurationDto.builder()
                        .keyManagementMethod("key")
                        .privateKey("private-key")
                        .hsm(toHSMProperties(hsmProperties(differentKeyId)))
                        .pkcs11Config(null)
                        .verificationMethod(baseConfigKeyId)
                        .build()
        );
    }

    @Test
    void createSigner_withUnknownKeyIdOverride_withHSM_andValidSigningKeys_shouldUseHSM_thenSuccess() throws Exception {
        SignatureConfigurationWithHsm cfg = baseConfiguration(baseConfigKeyId);
        var differentKeyId = baseConfigKeyId + "different-key";
        var pin = "pin";
        cfg.setHsm(hsmProperties(differentKeyId));
        cfg.setSigningKeys(List.of(keySignatureConfiguration(differentKeyId)));

        ConfigurationOverride override = new ConfigurationOverride(null, null, differentKeyId, pin);
        assertDoesNotThrow(() -> facade.createSigner(cfg, override));

        ArgumentCaptor<SignatureConfigurationDto> captor = ArgumentCaptor.forClass(SignatureConfigurationDto.class);
        verify(jwsSignatureService).createSigner(captor.capture(), eq(differentKeyId), eq(pin));
        assertThat(captor.getValue()).usingRecursiveComparison().isEqualTo(
                SignatureConfigurationDto.builder()
                        .keyManagementMethod("key")
                        .privateKey("private-key")
                        .hsm(toHSMProperties(hsmProperties(differentKeyId)))
                        .pkcs11Config(null)
                        .verificationMethod(baseConfigKeyId)
                        .build()
        );
    }

    @Test
    void createSigner_withoutMatchingSigningKeys_thenThrowsConfigurationException() {
        SignatureConfigurationWithHsm cfg = baseConfiguration(baseConfigKeyId);
        var differentKeyId = baseConfigKeyId + "different-key";
        var anotherDid = baseConfig + "-other";
        var anotherKeyId = anotherDid + "#key";
        cfg.setSigningKeys(List.of(keySignatureConfiguration(differentKeyId)));

        ConfigurationOverride override = new ConfigurationOverride(anotherDid, anotherKeyId, null, null);
        assertThrows(ConfigurationException.class, () -> facade.createSigner(cfg, override));
    }

    @Test
    void createSigner_withNullOverride_thenThrowsConfigurationException() {
        SignatureConfigurationWithHsm cfg = baseConfiguration(baseConfigKeyId);

        assertThrows(ConfigurationException.class, () -> facade.createSigner(cfg, null));
    }

    @Test
    void createSigner_withoutConfig_thenThrowsConfigurationException() {

        ConfigurationOverride override = new ConfigurationOverride(null, null, null, null);
        assertThrows(ConfigurationException.class, () -> facade.createSigner(null, override));
    }

    private SignatureConfigurationWithHsm baseConfiguration(String verificationMethod) {

        SignatureConfigurationWithHsm cfg = new SignatureConfigurationWithHsm();
        cfg.setKeyManagementMethod("key");
        cfg.setVerificationMethod(verificationMethod);
        cfg.setPrivateKey("private-key");

        return cfg;
    }

    private KeyOnlySignatureConfiguration keySignatureConfiguration(String verificationMethod) {

        KeyOnlySignatureConfiguration cfg = new KeyOnlySignatureConfiguration();
        cfg.setVerificationMethod(verificationMethod);
        cfg.setPrivateKey("private-key");

        return cfg;
    }

    private HSMProperties hsmProperties(String keyId) {

        HSMProperties hsm = new HSMProperties();
        hsm.setUserPin("user-pin");
        hsm.setKeyId(keyId);
        hsm.setKeyPin("hsm-key-pin");
        hsm.setPkcs11Config("pkcs11-hsm");
        hsm.setUser("user");
        hsm.setHost("hsm-host");
        hsm.setPort("1234");
        hsm.setPassword("password");
        hsm.setProxyUser("proxy-user");
        hsm.setProxyPassword("proxy-password");
        return hsm;
    }

    private HSMPropertiesDto toHSMProperties(HSMProperties hmsProps) {
        return HSMPropertiesDto.builder()
                .userPin(hmsProps.getUserPin())
                .keyId(hmsProps.getKeyId())
                .keyPin(hmsProps.getKeyPin())
                .pkcs11Config(hmsProps.getPkcs11Config())
                .user(hmsProps.getUser())
                .host(hmsProps.getHost())
                .port(hmsProps.getPort())
                .password(hmsProps.getPassword())
                .proxyUser(hmsProps.getProxyUser())
                .proxyPassword(hmsProps.getProxyPassword())
                .build();
    }
}
