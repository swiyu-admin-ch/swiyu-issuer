/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialEnvelopeDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.CredentialResponseDto;
import ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2.CredentialObjectDtoV2;
import ch.admin.bj.swiyu.issuer.api.oid4vci.issuance_v2.CredentialResponseDtoV2;
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

import java.util.*;

import static ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError.INVALID_CREDENTIAL_REQUEST;

@Getter
public abstract class CredentialBuilder {
    private final ApplicationProperties applicationProperties;
    private final IssuerMetadataTechnical issuerMetadata;
    private final DataIntegrityService dataIntegrityService;
    private final JWSSigner signer;
    private final StatusListRepository statusListRepository;
    private final CredentialOfferStatusRepository credentialOfferStatusRepository;
    private CredentialResponseEncryptor credentialResponseEncryptor;
    private CredentialOffer credentialOffer;
    private CredentialConfiguration credentialConfiguration;
    private Optional<DidJwk> holderBinding;
    private List<String> metadataCredentialsSupportedIds;

    CredentialBuilder(ApplicationProperties applicationProperties, IssuerMetadataTechnical issuerMetadata,
                      DataIntegrityService dataIntegrityService, JWSSigner signer,
                      StatusListRepository statusListRepository, CredentialOfferStatusRepository credentialOfferStatusRepository) {
        this.applicationProperties = applicationProperties;
        this.issuerMetadata = issuerMetadata;
        this.dataIntegrityService = dataIntegrityService;
        this.holderBinding = Optional.empty();
        this.signer = signer;
        this.statusListRepository = statusListRepository;
        this.credentialOfferStatusRepository = credentialOfferStatusRepository;
    }

    public CredentialBuilder credentialOffer(CredentialOffer credentialOffer) {
        this.credentialOffer = credentialOffer;
        this.credentialConfiguration = getOfferCredentialConfiguration(credentialOffer);
        return this;
    }

    public CredentialBuilder credentialResponseEncryption(CredentialResponseEncryptionClass credentialResponseEncryption) {
        this.credentialResponseEncryptor = new CredentialResponseEncryptor(issuerMetadata.getResponseEncryption(), credentialResponseEncryption);
        return this;
    }

    public CredentialEnvelopeDto buildCredential() {
        var credential = getCredential();
        var oid4vciCredential = new CredentialResponseDto(this.credentialConfiguration.getFormat(), credential, null);
        return buildEnvelopeDto(oid4vciCredential);
    }

    public CredentialEnvelopeDto buildCredentialV2() {
        // at the moment there is only 1 credential
        var credential = getCredential();
        var credentialResponseDtoV2 = new CredentialResponseDtoV2(List.of(new CredentialObjectDtoV2(credential)), null, null);

        return buildEnvelopeDto(credentialResponseDtoV2);
    }

    public CredentialEnvelopeDto buildDeferredCredentialV2(UUID transactionId) {
        var credentialResponseDtoV2 = new CredentialResponseDtoV2(null, transactionId.toString(), applicationProperties.getMinDeferredOfferIntervalSeconds());

        return buildEnvelopeDto(credentialResponseDtoV2, HttpStatus.ACCEPTED);
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
     * @param holderKeyJson Optional of the holderKey formatted as a json web key
     */
    public CredentialBuilder holderBinding(Optional<String> holderKeyJson) {
        this.holderBinding = holderKeyJson.map(s -> DidJwk.createFromJsonString(holderKeyJson.get()));
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
        return this.dataIntegrityService.getVerifiedOfferData(this.credentialOffer.getOfferData(), this.credentialOffer.getId());
    }

    /**
     * Create all status list references in the way they are to be added to the VC JSON
     * eg
     * <pre><code>
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
     *  </code></pre>
     */
    protected Map<String, Object> getStatusReferences() {
        VerifiableCredentialStatusFactory statusFactory = new VerifiableCredentialStatusFactory();
        HashMap<String, Object> statuses = new HashMap<>();
        Set<CredentialOfferStatus> byOfferStatusId = credentialOfferStatusRepository.findByOfferStatusId(this.credentialOffer.getId());

        return byOfferStatusId.stream()
                .map((CredentialOfferStatus credentialOfferStatus) -> statusFactory.createStatusListReference(credentialOfferStatus.getIndex(), getStatusList(credentialOfferStatus)))
                .map(VerifiableCredentialStatusReference::createVCRepresentation)
                .reduce(statuses, statusFactory::mergeStatus);
    }

    private StatusList getStatusList(CredentialOfferStatus credentialOfferStatus) {
        return statusListRepository.findById(credentialOfferStatus.getId().getStatusListId())
                .orElseThrow(() -> new CredentialException("StatusList not found for ID: " + credentialOfferStatus.getId().getStatusListId()));
    }

    abstract String getCredential();

    // abstract String getCredential(String proof);

    /**
     * Gets the credential configuration form the issuer metadata matching the credential supported id of the offer
     *
     * @param offer
     * @return the Credential Configuration
     */
    private CredentialConfiguration getOfferCredentialConfiguration(CredentialOffer offer) {
        return Optional.ofNullable(issuerMetadata.getCredentialConfigurationSupported().get(
                offer.getMetadataCredentialSupportedId().getFirst())).orElseThrow(() ->
                new Oid4vcException(INVALID_CREDENTIAL_REQUEST, "Requested Credential is not offered (anymore). Credential supported id was " + offer.getMetadataCredentialSupportedId().getFirst()));
    }

}