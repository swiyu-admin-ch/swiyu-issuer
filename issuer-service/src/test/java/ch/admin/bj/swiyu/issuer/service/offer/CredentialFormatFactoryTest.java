package ch.admin.bj.swiyu.issuer.service.offer;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.common.exception.ConfigurationException;
import ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusListRepository;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialConfiguration;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.service.CredentialBuilder;
import ch.admin.bj.swiyu.issuer.service.DataIntegrityService;
import ch.admin.bj.swiyu.issuer.service.JwsSignatureFacade;
import ch.admin.bj.swiyu.issuer.service.SdJwtCredential;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CredentialFormatFactoryTest {

    @Mock private ApplicationProperties applicationProperties;
    @Mock private IssuerMetadata issuerMetadata;
    @Mock private DataIntegrityService dataIntegrityService;
    @Mock private SdjwtProperties sdjwtProperties;
    @Mock private JwsSignatureFacade jwsSignatureFacade;
    @Mock private StatusListRepository statusListRepository;
    @Mock private CredentialOfferStatusRepository credentialOfferStatusRepository;

    @InjectMocks
    private CredentialFormatFactory factory;

    /**
     * Happy‑path: when the credential configuration exists and its format is
     * {@code vc+sd-jwt}, the factory must return an {@link SdJwtCredential}
     * instance.
     */
    @Test
    void getFormatBuilder_returnsSdJwtCredential_whenFormatIsVcSdJwt() {
        // arrange
        var configId = "test-config";
        var mockedConfig = mock(CredentialConfiguration.class);
        when(mockedConfig.getFormat()).thenReturn("vc+sd-jwt");

        Map<String, CredentialConfiguration> credentialConfigurationSupported = new HashMap<>();
        credentialConfigurationSupported.put(configId, mockedConfig);
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(credentialConfigurationSupported);

        // act
        CredentialBuilder builder = factory.getFormatBuilder(configId);

        // assert
        assertThat(builder).isInstanceOf(SdJwtCredential.class);
    }

    /**
     * When an unknown configuration identifier is supplied the factory must
     * raise an {@link Oid4vcException} with the error code
     * {@link CredentialRequestError#UNKNOWN_CREDENTIAL_CONFIGURATION}.
     */
    @Test
    void getFormatBuilder_unknownConfigurationIdentifier_throwsOid4vcException() {
        // arrange
        when(issuerMetadata.getCredentialConfigurationSupported())
                .thenReturn(Collections.emptyMap());

        // act / assert
        assertThatThrownBy(() -> factory.getFormatBuilder("unknown-id"))
                .isInstanceOf(Oid4vcException.class)
                .as("Should be unknown_credential_configuration error code")
                .matches(e -> ((Oid4vcException) e).getError() == CredentialRequestError.UNKNOWN_CREDENTIAL_CONFIGURATION);
    }

    /**
     * If the configuration exists but its {@code format} field is not supported,
     * the factory must throw a {@link ConfigurationException}.
     */
    @Test
    void getFormatBuilder_unknownFormat_throwsConfigurationException() {
        // arrange
        var configId = "unsupported-format-config";
        var mockedConfig = mock(CredentialConfiguration.class);
        when(mockedConfig.getFormat()).thenReturn("some-unsupported-format");

        Map<String, CredentialConfiguration> cfgMap = new HashMap<>();
        cfgMap.put(configId, mockedConfig);
        when(issuerMetadata.getCredentialConfigurationSupported()).thenReturn(cfgMap);

        // act / assert
        assertThatThrownBy(() -> factory.getFormatBuilder(configId))
            .as("Should indicate something is wrong with configuration done by the issuer")
            .isInstanceOf(ConfigurationException.class);
    }
}