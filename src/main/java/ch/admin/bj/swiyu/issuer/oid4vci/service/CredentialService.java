/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.service;

import ch.admin.bj.swiyu.issuer.oid4vci.api.*;
import ch.admin.bj.swiyu.issuer.oid4vci.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.oid4vci.common.config.OpenIdIssuerConfiguration;
import ch.admin.bj.swiyu.issuer.oid4vci.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.oid4vci.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.credentialoffer.CredentialOfferRepository;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.credentialoffer.CredentialStatus;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.credentialrequest.CredentialRequest;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.metadata.IssuerMetadataTechnical;
import com.nimbusds.jose.JWSSigner;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.util.Optional;
import java.util.UUID;

import static ch.admin.bj.swiyu.issuer.oid4vci.common.exception.CredentialRequestError.*;
import static ch.admin.bj.swiyu.issuer.oid4vci.service.mapper.CredentialRequestMapper.toCredentialRequest;
import static java.util.Objects.isNull;

@Service
@AllArgsConstructor
@Slf4j
public class CredentialService {

    private final CredentialOfferRepository credentialOfferRepository;
    private final IssuerMetadataTechnical issuerMetadata;
    private final CredentialFormatFactory vcFormatFactory;
    private final ApplicationProperties applicationProperties;
    private final JWSSigner signer;
    private final OpenIdIssuerConfiguration openIDConfiguration;

    @Transactional
    public CredentialEnvelopeDto createCredential(CredentialRequestDto credentialRequestDto, String accessToken) {

        var credentialRequest = toCredentialRequest(credentialRequestDto);

        CredentialOffer credentialOffer = getCredentialOfferByAccessToken(accessToken);

        // We have to check again that the Credential Status has not been changed to
        // catch race condition between holder & issuer
        if (!credentialOffer.getCredentialStatus().equals(CredentialStatus.IN_PROGRESS)) {
            throw OAuthException.invalidGrant(String.format(
                    "Offer is not valid anymore. The current offer state is %s." +
                            "The user should probably contact the business issuer about this.",
                    credentialOffer.getCredentialStatus()));
        }

        if (credentialOffer.hasTokenExpirationPassed()) {
            throw OAuthException.invalidRequest("AccessToken expired.");
        }

        var credentialConfiguration = issuerMetadata.getCredentialConfigurationById(
                credentialOffer.getMetadataCredentialSupportedId().getFirst());

        if (!credentialConfiguration.getFormat().equals(credentialRequest.getFormat())) {
            throw new Oid4vcException(UNSUPPORTED_CREDENTIAL_FORMAT, "Mismatch between requested and offered format.");
        }

        var holderPublicKey = getHolderPublicKey(credentialRequest, credentialOffer);

        var vcBuilder = vcFormatFactory
                // get first entry because we expect the list to only contain one item
                .getFormatBuilder(credentialOffer.getMetadataCredentialSupportedId().getFirst())
                .credentialOffer(credentialOffer)
                .credentialResponseEncryption(credentialRequest.getCredentialResponseEncryption())
                .holderBinding(holderPublicKey)
                .credentialType(credentialOffer.getMetadataCredentialSupportedId());

        CredentialEnvelopeDto responseEnvelope;

        // for deferred check if flag in the metadata set
        if (credentialOffer.isDeferred()) {
            var deferredData = new DeferredDataDto(UUID.randomUUID());

            responseEnvelope = vcBuilder.buildEnvelopeDto(deferredData);
            credentialOffer.markAsDeferred(deferredData.transactionId(), credentialRequest, holderPublicKey.orElse(null));
        } else {
            responseEnvelope = vcBuilder.buildCredential();
            credentialOffer.markAsIssued();
        }

        credentialOfferRepository.save(credentialOffer);
        return responseEnvelope;
    }

    @Transactional
    public CredentialEnvelopeDto createCredentialFromDeferredRequest(DeferredCredentialRequestDto deferredCredentialRequest,
                                                                     String accessToken) {
        CredentialOffer credentialOffer = getCredentialOfferByTransactionIdAndAccessToken(
                deferredCredentialRequest.transactionId(),
                accessToken);

        // We have to check again that the Credential Status has not been changed to
        // catch race condition between holder & issuer
        if (credentialOffer.getCredentialStatus() != CredentialStatus.READY) {
            throw new Oid4vcException(ISSUANCE_PENDING, "The credential is not marked as ready to be issued");
        }

        if (credentialOffer.hasTokenExpirationPassed()) {
            throw OAuthException.invalidRequest("AccessToken expired.");
        }

        var credentialRequest = credentialOffer.getCredentialRequest();

        if (isNull(credentialRequest)) {
            throw new IllegalArgumentException("Credential Request is missing");
        }

        // Get holder public key which was stored in the credential request
        Optional<String> holderPublicKey = Optional.of(credentialOffer.getHolderJWK());

        CredentialEnvelopeDto vc = vcFormatFactory
                // get first entry because we expect the list to only contain one item
                .getFormatBuilder(credentialOffer.getMetadataCredentialSupportedId().getFirst())
                .credentialOffer(credentialOffer)
                .credentialResponseEncryption(credentialRequest.getCredentialResponseEncryption())
                .holderBinding(holderPublicKey)
                .credentialType(credentialOffer.getMetadataCredentialSupportedId())
                .buildCredential();

        credentialOffer.markAsIssued();

        credentialOfferRepository.save(credentialOffer);
        return vc;
    }

    /**
     * Issues an OAuth token for a given pre-authorization code created by issuer mgmt
     *
     * @param preAuthCode Pre authorization code of holder
     * @return OAuth authorization token which can be used in credential service endpoint
     */
    @Transactional
    public OAuthTokenDto issueOAuthToken(String preAuthCode) {
        var offer = getCredentialOfferByPreAuthCode(preAuthCode);

        if (offer.getCredentialStatus() != CredentialStatus.OFFERED) {
            throw OAuthException.invalidGrant("Credential has already been used");
        }
        log.info("Pre-Authorized code consumed, sending Access Token {}. Management ID is {} and new status is {}",
                offer.getAccessToken(), offer.getId(), offer.getCredentialStatus());
        offer.markAsInProgress();
        offer.setTokenIssuanceTimestamp(applicationProperties.getTokenTTL());

        credentialOfferRepository.saveAndFlush(offer);

        return OAuthTokenDto.builder()
                .accessToken(offer.getAccessToken().toString())
                .expiresIn(applicationProperties.getTokenTTL())
                .cNonce(offer.getNonce().toString())
                .build();
    }

    private Optional<CredentialOffer> getNonExpiredCredentialOffer(Optional<CredentialOffer> credentialOffer) {
        return credentialOffer
                .map(offer -> {
                    if (offer.getCredentialStatus() != CredentialStatus.EXPIRED
                            && offer.hasExpirationTimeStampPassed()) {
                        offer.markAsExpired();
                        return credentialOfferRepository.save(offer);
                    }
                    return offer;
                });
    }

    private CredentialOffer getCredentialOfferByAccessToken(String accessToken) {
        var uuid = uuidOrException(accessToken);
        return getNonExpiredCredentialOffer(credentialOfferRepository.findByAccessToken(uuid))
                .orElseThrow(() -> OAuthException.invalidToken("Invalid accessToken"));
    }

    private CredentialOffer getCredentialOfferByTransactionIdAndAccessToken(UUID transactionId, String accessToken) {
        var credentialOffer = this.getCredentialOfferByAccessToken(accessToken);
        var storedTransactionId = credentialOffer.getTransactionId();

        if (isNull(storedTransactionId) || !storedTransactionId.equals(transactionId)) {
            throw new Oid4vcException(INVALID_CREDENTIAL_REQUEST, "Invalid transactional id");
        }

        return credentialOffer;
    }

    private CredentialOffer getCredentialOfferByPreAuthCode(String preAuthCode) {
        var uuid = uuidOrException(preAuthCode);
        return getNonExpiredCredentialOffer(credentialOfferRepository.findByPreAuthorizedCode(uuid))
                .orElseThrow(() -> OAuthException.invalidGrant("Invalid preAuthCode"));
    }

    private UUID uuidOrException(String preAuthCode) {
        UUID offerId;
        try {
            offerId = UUID.fromString(preAuthCode);
        } catch (IllegalArgumentException ex) {
            throw OAuthException.invalidRequest("Expecting a correct UUID");
        }
        return offerId;
    }

    /**
     * Validate and process the credentialRequest
     *
     * @param credentialRequest the credential request to be processed
     * @param credentialOffer   the credential offer for which the request was sent
     * @return the holder's public key or an empty optional
     * if for the offered credential no holder binding is required
     * @throws Oid4vcException if the credential request is invalid in some form
     */
    private Optional<String> getHolderPublicKey(CredentialRequest credentialRequest, CredentialOffer credentialOffer) {
        var credentialConfiguration = issuerMetadata.getCredentialConfigurationById(
                credentialOffer.getMetadataCredentialSupportedId().getFirst());

        // Process Holder Binding if a Proof Type is required
        var proofTypes = credentialConfiguration.getProofTypesSupported();
        if (proofTypes != null && !proofTypes.isEmpty()) {
            var requestProof = credentialRequest.getProof(applicationProperties.getAcceptableProofTimeWindowSeconds())
                    .orElseThrow(
                            () -> new Oid4vcException(INVALID_PROOF,
                                    "Proof must be provided for the requested credential"));
            var bindingProofType = Optional.of(proofTypes.get(requestProof.proofType.toString()))
                    .orElseThrow(() -> new Oid4vcException(INVALID_PROOF,
                            "Provided proof is not supported for the credential requested."));
            try {
                if (!requestProof.isValidHolderBinding(
                        (String) openIDConfiguration.getIssuerMetadata().get("credential_issuer"),
                        bindingProofType.getSupportedSigningAlgorithms(),
                        credentialOffer.getNonce(),
                        credentialOffer.getTokenExpirationTimestamp())) {
                    throw new Oid4vcException(INVALID_PROOF, "Presented proof was invalid!");
                }
            } catch (IOException e) {
                throw new Oid4vcException(INVALID_PROOF, "Presented proof was invalid!");
            }
            return Optional.of(requestProof.getBinding());
        }
        return Optional.empty();
    }
}