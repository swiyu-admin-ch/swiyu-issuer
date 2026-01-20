package ch.admin.bj.swiyu.issuer.service.credential;

import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialEndpointRequestDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialEnvelopeDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2.CredentialEndpointRequestDtoV2;
import ch.admin.bj.swiyu.issuer.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.ClientAgentInfo;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialManagement;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.service.OAuthService;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

import static ch.admin.bj.swiyu.issuer.service.mapper.CredentialRequestMapper.toCredentialRequest;

/**
 * Handles credential issuance flows for immediate and renewal scenarios.
 */
@Service
@AllArgsConstructor
public class CredentialIssuanceService {

    private final OAuthService oAuthService;
    private final CredentialOfferStateService credentialOfferStateService;
    private final CredentialEnvelopeService credentialEnvelopeService;
    private final CredentialRenewalService credentialRenewalService;

    /**
     * Issues a credential (OID4VCI 1.0).
     */
    @Deprecated(since = "OID4VCI 1.0")
    public CredentialEnvelopeDto createCredential(CredentialEndpointRequestDto credentialRequestDto,
                                                  String accessToken,
                                                  ClientAgentInfo clientInfo) {

        CredentialRequestClass credentialRequest = toCredentialRequest(credentialRequestDto);
        CredentialManagement mgmt = oAuthService.getCredentialManagementByAccessToken(accessToken);

        credentialOfferStateService.checkIfAnyOfferExpiredAndUpdate(mgmt);
        var credentialOffer = credentialOfferStateService.getFirstOffersInProgress(mgmt)
                .orElseThrow(() -> OAuthException.invalidGrant(
                        "Invalid accessToken"));

        return credentialEnvelopeService.createCredentialEnvelopeDto(
                credentialOffer,
                credentialRequest,
                clientInfo);
    }

    /**
     * Issues a credential (OID4VCI 2.0), including renewal flow.
     */
    public CredentialEnvelopeDto createCredentialV2(CredentialEndpointRequestDtoV2 credentialRequestDto,
                                                    String accessToken,
                                                    ClientAgentInfo clientInfo,
                                                    String dpopKey) {

        var credentialRequest = toCredentialRequest(credentialRequestDto);
        var mgmt = oAuthService.getCredentialManagementByAccessToken(accessToken);

        credentialOfferStateService.checkIfAnyOfferExpiredAndUpdate(mgmt);
        var credentialOffer = credentialOfferStateService.getFirstOffersInProgress(mgmt);

        if (credentialOffer.isPresent()) {
            return credentialEnvelopeService.createCredentialEnvelopeDtoV2(
                    credentialOffer.get(), credentialRequest, clientInfo, mgmt);
        }

        return credentialRenewalService.handleRenewalFlow(credentialRequest, mgmt, clientInfo, dpopKey);
    }
}

