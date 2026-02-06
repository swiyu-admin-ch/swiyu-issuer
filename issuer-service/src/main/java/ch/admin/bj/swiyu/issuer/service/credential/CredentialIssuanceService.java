package ch.admin.bj.swiyu.issuer.service.credential;

import ch.admin.bj.swiyu.issuer.dto.oid4vci.CredentialEndpointRequestDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.CredentialEnvelopeDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.issuance_v2.CredentialEndpointRequestDtoV2;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.service.OAuthService;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

import static ch.admin.bj.swiyu.issuer.service.credential.CredentialRequestMapper.toCredentialRequest;

/**
 * Service responsible for handling the issuance of credentials, including both OID4VCI 1.0 (deprecated) and 2.0 flows.
 * Supports immediate issuance, renewal, and offer expiration management.
 */
@Service
@AllArgsConstructor
public class CredentialIssuanceService {

    private final OAuthService oAuthService;
    private final CredentialEnvelopeService credentialEnvelopeService;
    private final CredentialRenewalService credentialRenewalService;
    private final CredentialStateMachine credentialStateMachine;
    private final CredentialOfferRepository credentialOfferRepository;

    /**
     * Issues a credential for OID4VCI 1.0 requests.
     *
     * @param credentialRequestDto the credential request DTO (OID4VCI 1.0)
     * @param accessToken the access token for the credential management session
     * @param clientInfo information about the client agent
     * @return the issued credential envelope
     * @deprecated since OID4VCI 1.0, use {@link #createCredentialV2} for newer flows
     */
    @Deprecated(since = "OID4VCI 1.0")
    public CredentialEnvelopeDto createCredential(CredentialEndpointRequestDto credentialRequestDto,
                                                  String accessToken,
                                                  ClientAgentInfo clientInfo) {

        CredentialRequestClass credentialRequest = toCredentialRequest(credentialRequestDto);
        CredentialManagement mgmt = oAuthService.getCredentialManagementByAccessToken(accessToken);

        checkIfAnyOfferExpiredAndUpdate(mgmt);
        var credentialOffer = getFirstOffersInProgress(mgmt)
                .orElseThrow(() -> OAuthException.invalidGrant(
                        "Invalid accessToken"));

        return credentialEnvelopeService.createCredentialEnvelopeDto(
                credentialOffer,
                credentialRequest,
                clientInfo);
    }

    /**
     * Issues a credential for OID4VCI 2.0 requests, including renewal flow if no offer is in progress.
     *
     * @param credentialRequestDto the credential request DTO (OID4VCI 2.0)
     * @param accessToken the access token for the credential management session
     * @param clientInfo information about the client agent
     * @param dpopKey the DPoP key for proof of possession
     * @return the issued credential envelope
     */
    public CredentialEnvelopeDto createCredentialV2(CredentialEndpointRequestDtoV2 credentialRequestDto,
                                                    String accessToken,
                                                    ClientAgentInfo clientInfo,
                                                    String dpopKey) {

        var credentialRequest = toCredentialRequest(credentialRequestDto);
        var mgmt = oAuthService.getCredentialManagementByAccessToken(accessToken);

        checkIfAnyOfferExpiredAndUpdate(mgmt);
        var credentialOffer = getFirstOffersInProgress(mgmt);

        if (credentialOffer.isPresent()) {
            return credentialEnvelopeService.createCredentialEnvelopeDtoV2(
                    credentialOffer.get(), credentialRequest, clientInfo, mgmt);
        }

        return credentialRenewalService.handleRenewalFlow(credentialRequest, mgmt, clientInfo, dpopKey);
    }

    /**
     * Returns the first credential offer in progress for the given management session.
     *
     * @param mgmt the credential management session
     * @return an optional containing the first in-progress offer, or empty if none found
     */
    private Optional<CredentialOffer> getFirstOffersInProgress(CredentialManagement mgmt) {
        return mgmt.getCredentialOffers().stream()
                .filter(offer -> offer.getCredentialStatus() == CredentialOfferStatusType.IN_PROGRESS)
                .findFirst();
    }

    /**
     * Checks all offers in the management session and terminates those that have expired.
     *
     * @param mgmt the credential management session
     */
    private void checkIfAnyOfferExpiredAndUpdate(CredentialManagement mgmt) {
        mgmt.getCredentialOffers().forEach(this::terminateExpiredOffer);
    }

    /**
     * Terminates the offer if it is not already terminated and has passed its expiration timestamp.
     *
     * @param offer the credential offer to check and possibly terminate
     */
    private void terminateExpiredOffer(CredentialOffer offer) {
        if (!offer.isTerminatedOffer() && offer.hasExpirationTimeStampPassed()) {
            credentialStateMachine.sendEventAndUpdateStatus(
                    offer, CredentialStateMachineConfig.CredentialOfferEvent.EXPIRE);
            credentialOfferRepository.save(offer);
        }
    }
}
