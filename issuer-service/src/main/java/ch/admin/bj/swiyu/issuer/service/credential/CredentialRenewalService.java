package ch.admin.bj.swiyu.issuer.service.credential;

import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialEnvelopeDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.common.exception.RenewalException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.service.CredentialManagementService;
import ch.admin.bj.swiyu.issuer.service.renewal.BusinessIssuerRenewalApiClient;
import ch.admin.bj.swiyu.issuer.service.renewal.RenewalRequestDto;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

/**
 * Handles credential renewal flow.
 */
@Slf4j
@Service
@AllArgsConstructor
public class CredentialRenewalService {

    private final ApplicationProperties applicationProperties;
    private final BusinessIssuerRenewalApiClient renewalApiClient;
    private final CredentialManagementService credentialManagementService;
    private final CredentialManagementRepository credentialManagementRepository;
    private final CredentialEnvelopeService credentialEnvelopeService;

    /**
     * Executes the renewal flow and returns the resulting credential envelope.
     */
    public CredentialEnvelopeDto handleRenewalFlow(CredentialRequestClass credentialRequest,
                                                   CredentialManagement mgmt,
                                                   ClientAgentInfo clientInfo,
                                                   String dpopKey) {

        if (mgmt.getCredentialManagementStatus() == CredentialStatusManagementType.REVOKED) {
            throw new RenewalException(HttpStatus.BAD_REQUEST, "Credential management is revoked, no renewal possible");
        }

        if (!applicationProperties.isRenewalFlowEnabled()) {
            log.info("Tried to renew credential for management id %s".formatted(mgmt.getId()));
            throw new RenewalException(HttpStatus.BAD_REQUEST, "No active offer found for %s and no renewal possible");
        }

        if (dpopKey == null) {
            throw OAuthException.invalidGrant("Invalid accessToken - no DPoP key present for refresh flow");
        }

        var requestedCredentialOffers = mgmt.getCredentialOffers().stream()
                .filter(offer -> offer.getCredentialStatus() == CredentialOfferStatusType.REQUESTED)
                .toList();

        if (!requestedCredentialOffers.isEmpty()) {
            throw new RenewalException(HttpStatus.TOO_MANY_REQUESTS, "Request already in progress");
        }

        var initialCredentialOfferForRenewal = this.credentialManagementService.createInitialCredentialOfferForRenewal(mgmt);

        var renewalData = new RenewalRequestDto(mgmt.getId(), initialCredentialOfferForRenewal.getId(), dpopKey);
        var renewedDataResponse = renewalApiClient.getRenewalData(renewalData);

        var offer = this.credentialManagementService.updateOfferFromRenewalResponse(renewedDataResponse, initialCredentialOfferForRenewal);

        CredentialEnvelopeDto envelopeDto = credentialEnvelopeService.createCredentialEnvelopeDtoV2(offer, credentialRequest, clientInfo, mgmt);

        mgmt.setRenewalResponseCnt(mgmt.getRenewalResponseCnt() + 1);
        credentialManagementRepository.save(mgmt);

        return envelopeDto;
    }
}

