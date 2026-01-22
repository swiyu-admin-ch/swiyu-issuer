package ch.admin.bj.swiyu.issuer.service.credential;

import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialEndpointRequestDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialEnvelopeDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2.CredentialEndpointRequestDtoV2;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;

import ch.admin.bj.swiyu.issuer.service.OAuthService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CredentialIssuanceServiceTest {

    @Mock
    private OAuthService oAuthService;
    @Mock
    private CredentialEnvelopeService credentialEnvelopeService;
    @Mock
    private CredentialRenewalService credentialRenewalService;
    @Mock
    private CredentialStateMachine credentialStateMachine;
    @Mock
    private CredentialOfferRepository credentialOfferRepository;

    private CredentialIssuanceService service;
    private AutoCloseable closeable;

    @BeforeEach
    void setUp() {
        closeable = MockitoAnnotations.openMocks(this);
        service = new CredentialIssuanceService(
                oAuthService,
                credentialEnvelopeService,
                credentialRenewalService,
                credentialStateMachine,
                credentialOfferRepository);
    }

    @AfterEach
    void tearDown() throws Exception {
        closeable.close();
    }

    @Test
    void createCredentialV2_withOffer_inProgressDelegatesToEnvelopeService() {
        var request = new CredentialEndpointRequestDtoV2("config-id", null, null);
        var offer = createOffer(CredentialOfferStatusType.IN_PROGRESS);
        var mgmt = createManagementWithOffers(offer);
        var envelope = new CredentialEnvelopeDto(null, null, null);

        when(oAuthService.getCredentialManagementByAccessToken("token"))
                .thenReturn(mgmt);
        when(credentialEnvelopeService.createCredentialEnvelopeDtoV2(eq(offer), any(), isNull(), eq(mgmt)))
                .thenReturn(envelope);

        var result = service.createCredentialV2(request, "token", null, "dpop");

        assertSame(envelope, result);
        verify(credentialEnvelopeService).createCredentialEnvelopeDtoV2(eq(offer), any(), isNull(), eq(mgmt));
        verify(credentialRenewalService, never()).handleRenewalFlow(any(), any(), any(), any());
    }

    @Test
    void createCredentialV2_withoutOffer_invokesRenewalFlow() {
        var request = new CredentialEndpointRequestDtoV2("config-id", null, null);
        var mgmt = createManagementWithOffers(
                createOffer(CredentialOfferStatusType.ISSUED));
        var envelope = new CredentialEnvelopeDto(null, null, null);

        when(oAuthService.getCredentialManagementByAccessToken("token"))
                .thenReturn(mgmt);
        when(credentialRenewalService.handleRenewalFlow(any(), eq(mgmt), isNull(), eq("dpop")))
                .thenReturn(envelope);

        var result = service.createCredentialV2(request, "token", null, "dpop");

        assertSame(envelope, result);
        verify(credentialEnvelopeService, never()).createCredentialEnvelopeDtoV2(any(), any(), any(), any());
        verify(credentialRenewalService).handleRenewalFlow(any(), eq(mgmt), isNull(), eq("dpop"));
    }

    @Test
    void createCredential_delegatesToEnvelopeService() {
        var request = new CredentialEndpointRequestDto("vc+sd-jwt", null, null);
        var offer = createOffer(CredentialOfferStatusType.IN_PROGRESS);
        var mgmt = createManagementWithOffers(offer);
        var envelope = new CredentialEnvelopeDto(null, null, null);

        when(oAuthService.getCredentialManagementByAccessToken("token"))
                .thenReturn(mgmt);
        when(credentialEnvelopeService.createCredentialEnvelopeDto(eq(offer), any(), isNull()))
                .thenReturn(envelope);

        var result = service.createCredential(request, "token", null);

        assertSame(envelope, result);
        verify(credentialEnvelopeService).createCredentialEnvelopeDto(eq(offer), any(), isNull());
    }

    private CredentialOffer createOffer(CredentialOfferStatusType status) {
        return CredentialOffer.builder()
                .credentialStatus(status)
                .metadataCredentialSupportedId(List.of("config-id"))
                .build();
    }

    private CredentialManagement createManagementWithOffers(CredentialOffer offer) {
        var mgmt = CredentialManagement.builder()
                .credentialManagementStatus(CredentialStatusManagementType.INIT)
                .accessToken(UUID.randomUUID())
                .build();
        offer.setCredentialManagement(mgmt);
        mgmt.addCredentialOffer(offer);
        return mgmt;
    }
}
