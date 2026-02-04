package ch.admin.bj.swiyu.issuer.service.credential;

import ch.admin.bj.swiyu.issuer.dto.callback.CallbackErrorEventTypeDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.CredentialEnvelopeDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.DeferredCredentialEndpointRequestDto;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.service.CredentialBuilder;
import ch.admin.bj.swiyu.issuer.service.offer.CredentialFormatFactory;
import ch.admin.bj.swiyu.issuer.service.enc.JweService;
import ch.admin.bj.swiyu.issuer.service.OAuthService;
import ch.admin.bj.swiyu.issuer.service.webhook.EventProducerService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError.CREDENTIAL_REQUEST_DENIED;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class DeferredCredentialServiceTest {

    @Mock
    private CredentialOfferRepository credentialOfferRepository;
    @Mock
    private CredentialManagementRepository credentialManagementRepository;
    @Mock
    private CredentialFormatFactory vcFormatFactory;
    @Mock
    private JweService jweService;
    @Mock
    private OAuthService oAuthService;
    @Mock
    private EventProducerService eventProducerService;
    @Mock
    private CredentialStateMachine credentialStateMachine;
    @Mock
    private CredentialBuilder builder;

    @InjectMocks
    private DeferredCredentialService service;

    private AutoCloseable closeable;

    @BeforeEach
    void init() {
        closeable = MockitoAnnotations.openMocks(this);
    }

    @AfterEach
    void tearDown() throws Exception {
        closeable.close();
    }

    @Test
    void createCredentialFromDeferredRequestV2_happyPath_buildsEnvelopeAndPersists() {
        var mgmt = CredentialManagement.builder()
                .credentialManagementStatus(CredentialStatusManagementType.ISSUED)
                .id(UUID.randomUUID())
                .renewalResponseCnt(0)
                .accessTokenExpirationTimestamp(Instant.now().plusSeconds(600).getEpochSecond())
                .build();
        var offer = CredentialOffer.builder()
                .credentialStatus(CredentialOfferStatusType.READY)
                .credentialManagement(mgmt)
                .transactionId(UUID.randomUUID())
                .metadataCredentialSupportedId(List.of("cfg"))
                .holderJWKs(List.of())
                .build();
        mgmt.addCredentialOffer(offer);

        IssuerMetadata metadata = IssuerMetadata.builder()
                .version("1.0.0")
                .build();

        var request = new CredentialRequestClass();
        offer.setCredentialRequest(request);

        when(oAuthService.getCredentialManagementByAccessToken("token")).thenReturn(mgmt);
        when(vcFormatFactory.getFormatBuilder("cfg")).thenReturn(builder);
        when(jweService.issuerMetadataWithEncryptionOptions()).thenReturn(metadata);
        when(builder.credentialOffer(offer)).thenReturn(builder);
        when(builder.credentialResponseEncryption(any(), any())).thenReturn(builder);
        when(builder.holderBindings(any())).thenReturn(builder);
        when(builder.credentialType(any())).thenReturn(builder);
        when(builder.buildCredentialEnvelopeV2()).thenReturn(new CredentialEnvelopeDto("h", "b", null));

        var result = service.createCredentialFromDeferredRequestV2(
                new DeferredCredentialEndpointRequestDto(offer.getTransactionId(), null),
                "token");

        assertThat(result).isNotNull();
        verify(credentialOfferRepository).save(offer);
        verify(credentialManagementRepository).save(mgmt);
        verify(credentialStateMachine).sendEventAndUpdateStatus(offer, CredentialStateMachineConfig.CredentialOfferEvent.ISSUE);
        verify(credentialStateMachine).sendEventAndUpdateStatus(mgmt, CredentialStateMachineConfig.CredentialManagementEvent.ISSUE);
    }

    @Test
    void createCredentialFromDeferredRequestV2_not_Ready() {
        var mgmt = CredentialManagement.builder()
                .credentialManagementStatus(CredentialStatusManagementType.ISSUED)
                .id(UUID.randomUUID())
                .renewalResponseCnt(0)
                .accessTokenExpirationTimestamp(Instant.now().plusSeconds(600).getEpochSecond())
                .build();
        var offer = CredentialOffer.builder()
                .credentialStatus(CredentialOfferStatusType.DEFERRED)
                .credentialManagement(mgmt)
                .transactionId(UUID.randomUUID())
                .metadataCredentialSupportedId(List.of("cfg"))
                .holderJWKs(List.of())
                .build();
        mgmt.addCredentialOffer(offer);

        IssuerMetadata metadata = IssuerMetadata.builder()
                .version("1.0.0")
                .build();

        var request = new CredentialRequestClass();
        offer.setCredentialRequest(request);

        when(oAuthService.getCredentialManagementByAccessToken("token")).thenReturn(mgmt);
        when(vcFormatFactory.getFormatBuilder("cfg")).thenReturn(builder);
        when(jweService.issuerMetadataWithEncryptionOptions()).thenReturn(metadata);
        when(builder.credentialOffer(offer)).thenReturn(builder);
        when(builder.credentialResponseEncryption(any(), any())).thenReturn(builder);
        when(builder.holderBindings(any())).thenReturn(builder);
        when(builder.credentialType(any())).thenReturn(builder);
        when(builder.buildCredentialEnvelopeV2()).thenReturn(new CredentialEnvelopeDto("h", "b", null));

        service.createCredentialFromDeferredRequestV2(
                new DeferredCredentialEndpointRequestDto(offer.getTransactionId(), null),
                "token");

    }

    @Test
    void getMetadataCredentialSupportedId_missing_throws() {
        var offer = CredentialOffer.builder().build();
        assertThatThrownBy(() -> service.getMetadataCredentialSupportedId(offer))
                .isInstanceOf(Oid4vcException.class)
                .hasMessageContaining("metadata_credential_supported_id")
                .extracting("error")
                .isEqualTo(CREDENTIAL_REQUEST_DENIED);
    }

    @Test
    void validateOfferProcessable_rejectsNonProcessable() {
        var offer = mock(CredentialOffer.class);
        when(offer.isProcessableOffer()).thenReturn(false);

        assertThatThrownBy(() -> service.validateOfferProcessable(offer))
                .isInstanceOf(Oid4vcException.class)
                .hasMessageContaining("cancelled or expired");
    }

    @Test
    void validateTokenNotExpired_rejectsExpired() {
        var offer = CredentialOffer.builder().id(UUID.randomUUID()).build();
        var mgmt = mock(CredentialManagement.class);
        when(mgmt.hasTokenExpirationPassed()).thenReturn(true);

        assertThatThrownBy(() -> service.validateTokenNotExpired(offer, mgmt))
                .isInstanceOf(OAuthException.class)
                .hasMessageContaining("AccessToken expired");
        verify(eventProducerService).produceErrorEvent(
                eq("AccessToken expired, offer is stuck in READY"),
                eq(CallbackErrorEventTypeDto.OAUTH_TOKEN_EXPIRED),
                eq(offer));
    }

    @Test
    void validateCredentialRequestPresent_rejectsMissing() {
        var offer = CredentialOffer.builder().build();

        assertThatThrownBy(() -> service.validateCredentialRequestPresent(offer))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Credential Request is missing");
    }
}
