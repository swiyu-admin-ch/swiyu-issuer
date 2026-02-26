package ch.admin.bj.swiyu.issuer.service.credential;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.common.exception.RenewalException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.CredentialEnvelopeDto;
import ch.admin.bj.swiyu.issuer.service.management.CredentialManagementService;
import ch.admin.bj.swiyu.issuer.service.renewal.BusinessIssuerRenewalApiClient;
import ch.admin.bj.swiyu.issuer.service.renewal.RenewalRequestDto;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

/**
 * Orchestrates the credential renewal lifecycle: validates eligibility, fetches renewal data,
 * updates the credential offer, builds the envelope, and persists state.
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
     * Runs the end-to-end renewal flow for a credential management record.
     *
     * @param credentialRequest the credential request details provided by the client
     * @param mgmt              the credential management aggregate to validate and update
     * @param clientInfo        metadata about the calling client agent
     * @param dpopKey           the DPoP public key associated with the access token
     * @return the envelope containing the renewed credential offer
     * @throws RenewalException when renewal is disallowed or already in progress
     * @throws OAuthException   when the DPoP key is missing or invalid for renewal
     */
    public CredentialEnvelopeDto handleRenewalFlow(CredentialRequestClass credentialRequest,
                                                   CredentialManagement mgmt,
                                                   ClientAgentInfo clientInfo,
                                                   String dpopKey) {

        ensureManagementNotRevokedOrSuspended(mgmt);
        ensureRenewalFlowEnabled(mgmt);
        ensureDpopKeyPresent(dpopKey);
        ensureNoPendingRenewalRequest(mgmt);

        var initialCredentialOfferForRenewal = credentialManagementService.createInitialCredentialOfferForRenewal(mgmt);
        var renewalData = buildRenewalRequestDto(mgmt, initialCredentialOfferForRenewal, dpopKey);
        var renewedDataResponse = renewalApiClient.getRenewalData(renewalData);

        var offer = credentialManagementService.updateOfferFromRenewalResponse(renewedDataResponse, initialCredentialOfferForRenewal);
        var envelopeDto = credentialEnvelopeService.createCredentialEnvelopeDtoV2(offer, credentialRequest, clientInfo, mgmt);

        incrementRenewalResponseCount(mgmt);
        credentialManagementRepository.save(mgmt);

        return envelopeDto;
    }

    void ensureManagementNotRevokedOrSuspended(CredentialManagement mgmt) {
        if (mgmt.getCredentialManagementStatus() == CredentialStatusManagementType.REVOKED || mgmt.getCredentialManagementStatus() == CredentialStatusManagementType.SUSPENDED) {
            throw new RenewalException(HttpStatus.BAD_REQUEST, "Credential management is %s, no renewal possible".formatted(mgmt.getCredentialManagementStatus().name()));
        }
    }

    void ensureRenewalFlowEnabled(CredentialManagement mgmt) {
        if (!applicationProperties.isRenewalFlowEnabled()) {
            log.info("Tried to renew credential for management id %s".formatted(mgmt.getId()));
            throw new RenewalException(HttpStatus.BAD_REQUEST, "Credential renewal is not allowed".formatted(mgmt.getId()));
        }
    }

    void ensureDpopKeyPresent(String dpopKey) {
        if (dpopKey == null) {
            throw OAuthException.invalidGrant("Invalid accessToken - no DPoP key present for refresh flow");
        }
    }

    void ensureNoPendingRenewalRequest(CredentialManagement mgmt) {
        var requestedCredentialOffers = mgmt.getCredentialOffers().stream()
                .filter(offer -> offer.getCredentialStatus() == CredentialOfferStatusType.REQUESTED)
                .toList();

        if (!requestedCredentialOffers.isEmpty()) {
            throw new RenewalException(HttpStatus.TOO_MANY_REQUESTS, "Request already in progress");
        }
    }

    RenewalRequestDto buildRenewalRequestDto(CredentialManagement mgmt, CredentialOffer initialOffer, String dpopKey) {
        return new RenewalRequestDto(mgmt.getId(), initialOffer.getId(), dpopKey);
    }

    void incrementRenewalResponseCount(CredentialManagement mgmt) {
        mgmt.setRenewalResponseCnt(mgmt.getRenewalResponseCnt() + 1);
    }
}