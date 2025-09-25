/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialEnvelopeDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.DeferredDataDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2.CredentialEndpointResponseDtoV2;
import ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2.CredentialObjectDtoV2;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.CredentialException;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.*;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialResponseEncryptionClass;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.encryption.CredentialResponseEncryptor;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.DidJwk;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialConfiguration;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadataTechnical;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSSigner;
import lombok.Getter;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.util.CollectionUtils;

import java.util.*;

import static ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError.INVALID_CREDENTIAL_REQUEST;

@Getter
public abstract class CredentialBuilder {
    private final ApplicationProperties applicationProperties;
    private final IssuerMetadataTechnical issuerMetadata;
    private final DataIntegrityService dataIntegrityService;
    private final StatusListRepository statusListRepository;
    private final CredentialOfferStatusRepository credentialOfferStatusRepository;
    private final SignatureService signatureService;
    private CredentialResponseEncryptor credentialResponseEncryptor;
    private CredentialOffer credentialOffer;
    private CredentialConfiguration credentialConfiguration;
    private List<DidJwk> holderBindings = new ArrayList<>();
    private List<String> metadataCredentialsSupportedIds;

    CredentialBuilder(ApplicationProperties applicationProperties,
                      IssuerMetadataTechnical issuerMetadata,
                      DataIntegrityService dataIntegrityService,
                      StatusListRepository statusListRepository,
                      SignatureService signatureService,
                      CredentialOfferStatusRepository credentialOfferStatusRepository) {
        this.applicationProperties = applicationProperties;
        this.issuerMetadata = issuerMetadata;
        this.dataIntegrityService = dataIntegrityService;
        this.statusListRepository = statusListRepository;
        this.credentialOfferStatusRepository = credentialOfferStatusRepository;
        this.signatureService = signatureService;
    }

    public CredentialBuilder credentialOffer(CredentialOffer credentialOffer) {
        this.credentialOffer = credentialOffer;
        this.credentialConfiguration = getOfferCredentialConfiguration(credentialOffer);
        return this;
    }

    public CredentialBuilder credentialResponseEncryption(
            CredentialResponseEncryptionClass credentialResponseEncryption) {
        this.credentialResponseEncryptor = new CredentialResponseEncryptor(issuerMetadata.getResponseEncryption(),
                credentialResponseEncryption);
        return this;
    }

    public CredentialEnvelopeDto buildCredentialEnvelope() {
        var credential = getCredential(this.holderBindings.isEmpty() ? null : this.holderBindings.getFirst());
        var oid4vciCredential = new HashMap<String, String>();
        oid4vciCredential.put("format", this.credentialConfiguration.getFormat());
        oid4vciCredential.put("credential", credential);
        return buildEnvelopeDto(oid4vciCredential);
    }

    public CredentialEnvelopeDto buildCredentialEnvelopeV2() {
        // if no holder bindings are set, we only create 1 credential
        List<CredentialObjectDtoV2> credentials = new ArrayList<>();
        if (CollectionUtils.isEmpty(this.holderBindings)) {
            var credential = new CredentialObjectDtoV2(getCredential(null));
            credentials.add(credential);
        } else {
            credentials.addAll(this.holderBindings.stream()
                    .map(this::getCredential)
                    .map(CredentialObjectDtoV2::new)
                    .toList());
        }
        var credentialResponseDtoV2 = new CredentialEndpointResponseDtoV2(credentials, null, null);

        return buildEnvelopeDto(credentialResponseDtoV2);
    }

    public CredentialEnvelopeDto buildDeferredCredentialV2(UUID transactionId) {
        var credentialResponseDtoV2 = new CredentialEndpointResponseDtoV2(null, transactionId.toString(),
                applicationProperties.getMinDeferredOfferIntervalSeconds());

        return buildEnvelopeDto(credentialResponseDtoV2, HttpStatus.ACCEPTED);
    }

    public CredentialEnvelopeDto buildDeferredCredential(UUID transactionId) {
        var deferredResponse = new DeferredDataDto(transactionId);

        return buildEnvelopeDto(deferredResponse, HttpStatus.ACCEPTED);
    }

    public CredentialEnvelopeDto buildEnvelopeDto(Object payload) {

        return buildEnvelopeDto(payload, HttpStatus.OK);
    }

    public CredentialEnvelopeDto buildEnvelopeDto(Object payload, HttpStatus httpStatus) {
        var payloadJson = "";
        try {
            payloadJson = new ObjectMapper().writeValueAsString(payload);
        } catch (JsonProcessingException e) {
            throw new CredentialException(e.getMessage());
        }
        var contentType = MediaType.APPLICATION_JSON_VALUE;
        if (getCredentialResponseEncryptor().isEncryptionRequired()) {
            payloadJson = getCredentialResponseEncryptor().encryptResponse(payloadJson);
            contentType = "application/jwt";
        }

        return new CredentialEnvelopeDto(contentType, payloadJson, httpStatus);
    }

    /**
     * Sets the holder binding for the credential. If not set, the credential will
     * be issued without a holder binding.
     *
     * @param holderKeys List of JSON string representing the holder's JWK.
     * @return the updated CredentialBuilder instance.
     */
    public CredentialBuilder holderBindings(List<String> holderKeys) {

        this.holderBindings = !CollectionUtils.isEmpty(holderKeys)
                ? holderKeys.stream().map(DidJwk::createFromJsonString).toList()
                : List.of();
        return this;
    }

    /**
     * Sets the list of supported credential IDs for the credential type.
     *
     * @param metadataCredentialsSupportedIds List of supported credential IDs.
     * @return the updated CredentialBuilder instance.
     */
    public CredentialBuilder credentialType(List<String> metadataCredentialsSupportedIds) {
        this.metadataCredentialsSupportedIds = metadataCredentialsSupportedIds;
        return this;
    }

    /**
     * Unpacks the credential offer data and checks the integrity, if applicable
     *
     * @return the data as to be used in credentialSubject
     */
    protected Map<String, Object> getOfferData() {
        return this.dataIntegrityService.getVerifiedOfferData(this.credentialOffer.getOfferData(),
                this.credentialOffer.getId());
    }

    abstract JWSSigner createSigner();

    /**
     * Create all status list references in the way they are to be added to the VC
     * JSON
     * eg
     *
     * <pre>
     * <code>
     *    {
     *      "status": {
     *           "status_list": {
     *              "idx": 0,
     *              "uri": "https://example.com/statuslists/1"
     *          }
     *      },
     *      "credentialStatus": {
     *          "id": "https://university.example/credentials/status/3#94567",
     *          "type": "BitstringStatusListEntry",
     *          "statusPurpose": "revocation",
     *          "statusListIndex": "94567",
     *          "statusListCredential": "https://university.example/credentials/status/3"
     *      }
     *   }
     *  </code>
     * </pre>
     */
    protected Map<String, Object> getStatusReferences() {
        VerifiableCredentialStatusFactory statusFactory = new VerifiableCredentialStatusFactory();
        HashMap<String, Object> statuses = new HashMap<>();
        Set<CredentialOfferStatus> byOfferStatusId = credentialOfferStatusRepository
                .findByOfferStatusId(this.credentialOffer.getId());

        return byOfferStatusId.stream()
                .map((CredentialOfferStatus credentialOfferStatus) -> statusFactory.createStatusListReference(
                        credentialOfferStatus.getIndex(), getStatusList(credentialOfferStatus)))
                .map(VerifiableCredentialStatusReference::createVCRepresentation)
                .reduce(statuses, statusFactory::mergeStatus);
    }

    private StatusList getStatusList(CredentialOfferStatus credentialOfferStatus) {
        return statusListRepository.findById(credentialOfferStatus.getId().getStatusListId())
                .orElseThrow(() -> new CredentialException(
                        "StatusList not found for ID: " + credentialOfferStatus.getId().getStatusListId()));
    }

    abstract String getCredential(DidJwk didJwk);

    /**
     * Gets the credential configuration form the issuer metadata matching the
     * credential supported id of the offer
     *
     * @param offer
     * @return the Credential Configuration
     */
    private CredentialConfiguration getOfferCredentialConfiguration(CredentialOffer offer) {
        return Optional.ofNullable(issuerMetadata.getCredentialConfigurationSupported().get(
                        offer.getMetadataCredentialSupportedId().getFirst()))
                .orElseThrow(() -> new Oid4vcException(INVALID_CREDENTIAL_REQUEST,
                        "Requested Credential is not offered (anymore). Credential supported id was "
                                + offer.getMetadataCredentialSupportedId().getFirst()));
    }

}