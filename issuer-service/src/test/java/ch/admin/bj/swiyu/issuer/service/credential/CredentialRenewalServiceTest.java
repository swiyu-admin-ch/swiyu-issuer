package ch.admin.bj.swiyu.issuer.service.credential;

import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialEnvelopeDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.common.exception.RenewalException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.service.CredentialManagementService;
import ch.admin.bj.swiyu.issuer.service.renewal.BusinessIssuerRenewalApiClient;
import ch.admin.bj.swiyu.issuer.service.renewal.RenewalResponseDto;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.http.HttpStatus;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class CredentialRenewalServiceTest {

    @Mock
    private ApplicationProperties applicationProperties;
    @Mock
    private BusinessIssuerRenewalApiClient renewalApiClient;
    @Mock
    private CredentialManagementService credentialManagementService;
    @Mock
    private CredentialManagementRepository credentialManagementRepository;
    @Mock
    private CredentialEnvelopeService credentialEnvelopeService;

    @InjectMocks
    private CredentialRenewalService service;
    private AutoCloseable closeable;

    @BeforeEach
    void init() {
        closeable = MockitoAnnotations.openMocks(this);
        when(applicationProperties.isRenewalFlowEnabled()).thenReturn(true);
    }

    @AfterEach
    void tearDown() throws Exception {
        closeable.close();
    }

    @Test
    void handleRenewalFlow_happyPath_executesStepsAndPersists() {
        var mgmt = CredentialManagement.builder()
                .credentialManagementStatus(CredentialStatusManagementType.ISSUED)
                .credentialOffers(Set.of())
                .renewalResponseCnt(0)
                .id(UUID.randomUUID())
                .build();
        var initialOffer = CredentialOffer.builder().id(UUID.randomUUID()).build();
        var renewalResponse = new RenewalResponseDto(
                List.of("config-id"),
                null,
                null,
                Instant.now(),
                Instant.now(),
                List.of(),
                null);
        var updatedOffer = CredentialOffer.builder().id(UUID.randomUUID()).build();
        @SuppressWarnings("deprecation")
		var request = new CredentialRequestClass();
        var envelope = new CredentialEnvelopeDto("h", "b", HttpStatus.OK);

        when(credentialManagementService.createInitialCredentialOfferForRenewal(mgmt)).thenReturn(initialOffer);
        when(renewalApiClient.getRenewalData(any())).thenReturn(renewalResponse);
        when(credentialManagementService.updateOfferFromRenewalResponse(renewalResponse, initialOffer)).thenReturn(updatedOffer);
        when(credentialEnvelopeService.createCredentialEnvelopeDtoV2(updatedOffer, request, null, mgmt)).thenReturn(envelope);

        var result = service.handleRenewalFlow(request, mgmt, null, "dpop-key");

        assertThat(result).isEqualTo(envelope);
        verify(credentialManagementRepository).save(mgmt);
        assertThat(mgmt.getRenewalResponseCnt()).isEqualTo(1);
    }

    @Test
    void ensureManagementNotRevoked_rejectsRevoked() {
        var mgmt = CredentialManagement.builder()
                .credentialManagementStatus(CredentialStatusManagementType.REVOKED)
                .build();

        assertThatThrownBy(() -> service.ensureManagementNotRevoked(mgmt))
                .isInstanceOf(RenewalException.class)
                .hasMessageContaining("revoked");
    }

    @Test
    void ensureRenewalFlowEnabled_rejectsWhenDisabled() {
        var mgmt = CredentialManagement.builder()
                .credentialManagementStatus(CredentialStatusManagementType.ISSUED)
                .id(UUID.randomUUID())
                .build();
        when(applicationProperties.isRenewalFlowEnabled()).thenReturn(false);

        assertThatThrownBy(() -> service.ensureRenewalFlowEnabled(mgmt))
                .isInstanceOf(RenewalException.class)
                .hasMessageContaining("No active offer");
    }

    @Test
    void ensureDpopKeyPresent_rejectsWhenMissing() {
        assertThatThrownBy(() -> service.ensureDpopKeyPresent(null))
                .isInstanceOf(OAuthException.class)
                .hasMessageContaining("no DPoP key present");
    }

    @Test
    void ensureNoPendingRenewalRequest_rejectsWhenRequestedOfferExists() {
        var pendingOffer = CredentialOffer.builder()
                .credentialStatus(CredentialOfferStatusType.REQUESTED)
                .build();
        var mgmt = CredentialManagement.builder()
                .credentialOffers(Set.of(pendingOffer))
                .build();

        assertThatThrownBy(() -> service.ensureNoPendingRenewalRequest(mgmt))
                .isInstanceOf(RenewalException.class)
                .hasMessageContaining("Request already in progress");
    }

    @Test
    void buildRenewalRequestDto_includesIdsAndDpopKey() {
        var mgmtId = UUID.randomUUID();
        var offerId = UUID.randomUUID();
        var dto = service.buildRenewalRequestDto(
                CredentialManagement.builder().id(mgmtId).build(),
                CredentialOffer.builder().id(offerId).build(),
                "dpop");

        assertThat(dto.managementId()).isEqualTo(mgmtId);
        assertThat(dto.offerId()).isEqualTo(offerId);
        assertThat(dto.dpopKey()).isEqualTo("dpop");
    }

    @Test
    void incrementRenewalResponseCount_incrementsCounter() {
        var mgmt = CredentialManagement.builder()
                .credentialManagementStatus(CredentialStatusManagementType.ISSUED)
                .renewalResponseCnt(2)
                .build();

        service.incrementRenewalResponseCount(mgmt);

        assertThat(mgmt.getRenewalResponseCnt()).isEqualTo(3);
    }
}
