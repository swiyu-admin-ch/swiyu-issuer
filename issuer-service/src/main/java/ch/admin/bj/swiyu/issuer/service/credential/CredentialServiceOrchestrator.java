package ch.admin.bj.swiyu.issuer.service.credential;

import ch.admin.bj.swiyu.issuer.domain.credentialoffer.ClientAgentInfo;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.CredentialEnvelopeDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.DeferredCredentialEndpointRequestDto;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.issuance.CreateCredentialRequestDto;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Facade delegating credential-related operations to specialized services.
 */
@Service
@AllArgsConstructor
public class CredentialServiceOrchestrator {

    private final CredentialIssuanceService credentialIssuanceService;
    private final DeferredCredentialService deferredCredentialService;

    /**
     * Issues a credential (OID4VCI 2.0).
     */
    @Transactional
    public CredentialEnvelopeDto createCredential(CreateCredentialRequestDto credentialRequestDto,
                                                  String accessToken,
                                                  ClientAgentInfo clientInfo,
                                                  String dpopKey) {
        return credentialIssuanceService.createCredential(credentialRequestDto, accessToken, clientInfo, dpopKey);
    }

    /**
     * Issues a deferred credential (OID4VCI 2.0).
     */
    @Transactional
    public CredentialEnvelopeDto createCredentialFromDeferredRequest(
            DeferredCredentialEndpointRequestDto deferredCredentialRequest,
            String accessToken) {
        return deferredCredentialService.createCredentialFromDeferredRequest(deferredCredentialRequest, accessToken);
    }
}

