package ch.admin.bj.swiyu.issuer.service.credential;

import ch.admin.bj.swiyu.issuer.dto.oid4vci.CredentialEnvelopeDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialConfiguration;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.service.CredentialBuilder;
import ch.admin.bj.swiyu.issuer.service.offer.CredentialFormatFactory;
import ch.admin.bj.swiyu.issuer.service.enc.JweService;
import ch.admin.bj.swiyu.issuer.service.webhook.EventProducerService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class CredentialEnvelopeServiceTest {

    @Mock
    private CredentialFormatFactory credentialFormatFactory;
    @Mock
    private JweService jweService;
    @Mock
    private HolderBindingService holderBindingService;
    @Mock
    private EventProducerService eventProducerService;
    @Mock
    private IssuerMetadata issuerMetadata;
    @Mock
    private CredentialStateMachine credentialStateMachine;
    @Mock
    private CredentialOfferRepository credentialOfferRepository;
    @Mock
    private CredentialManagementRepository credentialManagementRepository;
    @Mock
    private ApplicationProperties applicationProperties;
    @Mock
    private CredentialBuilder credentialBuilder;

    private CredentialEnvelopeService service;
    private AutoCloseable closeable;

    @BeforeEach
    void setUp() {
        closeable = MockitoAnnotations.openMocks(this);
        service = new CredentialEnvelopeService(
                credentialFormatFactory,
                jweService,
                holderBindingService,
                eventProducerService,
                issuerMetadata,
                credentialStateMachine,
                credentialOfferRepository,
                credentialManagementRepository,
                applicationProperties);
    }

    @AfterEach
    void tearDown() throws Exception {
        closeable.close();
    }

    @Test
    void issueCredential_immediateBranch_executesIssueEventsAndPersists() {
        var offer = CredentialOffer.builder().build();
        offer.setCredentialOfferStatusJustForTestUsage(CredentialOfferStatusType.IN_PROGRESS);
        offer.setMetadataCredentialSupportedId(List.of("config-id"));
        var mgmt = CredentialManagement.builder().build();
        mgmt.setAccessTokenExpirationTimestamp(Instant.now().plusSeconds(60).getEpochSecond());
        offer.setCredentialManagement(mgmt);

        var request = new CredentialRequestClass();
        request.setFormat("dc+sd-jwt");

        var credentialConfiguration = new CredentialConfiguration();
        credentialConfiguration.setFormat("dc+sd-jwt");

        when(issuerMetadata.getCredentialConfigurationById("config-id"))
                .thenReturn(credentialConfiguration);
        when(holderBindingService.getHolderPublicKey(any(), any())).thenReturn(Optional.empty());
        when(credentialFormatFactory.getFormatBuilder("config-id")).thenReturn(credentialBuilder);
        when(jweService.issuerMetadataWithEncryptionOptions()).thenReturn(issuerMetadata);
        when(credentialBuilder.credentialOffer(offer)).thenReturn(credentialBuilder);
        when(credentialBuilder.credentialResponseEncryption(any(), any())).thenReturn(credentialBuilder);
        when(credentialBuilder.holderBindings(any())).thenReturn(credentialBuilder);
        when(credentialBuilder.credentialType(any())).thenReturn(credentialBuilder);
        when(credentialBuilder.buildCredentialEnvelope()).thenReturn(new CredentialEnvelopeDto(null, null, null));

        service.createCredentialEnvelopeDto(offer, request, null);

        verify(credentialStateMachine).sendEventAndUpdateStatus(offer, CredentialStateMachineConfig.CredentialOfferEvent.ISSUE);
        verify(credentialStateMachine).sendEventAndUpdateStatus(mgmt, CredentialStateMachineConfig.CredentialManagementEvent.ISSUE);
        verify(credentialOfferRepository).save(offer);
        verify(credentialManagementRepository).save(mgmt);
    }

    @Test
    void issueCredentialV2_immediateBranch_executesIssueEventsAndPersists() {
        var offer = CredentialOffer.builder().build();
        offer.setCredentialOfferStatusJustForTestUsage(CredentialOfferStatusType.IN_PROGRESS);
        offer.setMetadataCredentialSupportedId(List.of("config-id"));
        var mgmt = CredentialManagement.builder().build();
        mgmt.setAccessTokenExpirationTimestamp(Instant.now().plusSeconds(60).getEpochSecond());
        offer.setCredentialManagement(mgmt);

        var request = new CredentialRequestClass();
        request.setFormat("dc+sd-jwt");

        var credentialConfiguration = new CredentialConfiguration();
        credentialConfiguration.setFormat("dc+sd-jwt");

        when(issuerMetadata.getCredentialConfigurationById("config-id"))
                .thenReturn(credentialConfiguration);
        when(holderBindingService.getValidateHolderPublicKeys(any(), any())).thenReturn(List.of());
        when(credentialFormatFactory.getFormatBuilder("config-id")).thenReturn(credentialBuilder);
        when(jweService.issuerMetadataWithEncryptionOptions()).thenReturn(issuerMetadata);
        when(credentialBuilder.credentialOffer(offer)).thenReturn(credentialBuilder);
        when(credentialBuilder.credentialResponseEncryption(any(), any())).thenReturn(credentialBuilder);
        when(credentialBuilder.holderBindings(any())).thenReturn(credentialBuilder);
        when(credentialBuilder.credentialType(any())).thenReturn(credentialBuilder);
        when(credentialBuilder.buildCredentialEnvelopeV2()).thenReturn(new CredentialEnvelopeDto(null, null, null));

        service.createCredentialEnvelopeDtoV2(offer, request, null, mgmt);

        verify(credentialStateMachine).sendEventAndUpdateStatus(offer, CredentialStateMachineConfig.CredentialOfferEvent.ISSUE);
        verify(credentialStateMachine).sendEventAndUpdateStatus(mgmt, CredentialStateMachineConfig.CredentialManagementEvent.ISSUE);
        verify(credentialOfferRepository).save(offer);
        verify(credentialManagementRepository).save(mgmt);
    }


}
