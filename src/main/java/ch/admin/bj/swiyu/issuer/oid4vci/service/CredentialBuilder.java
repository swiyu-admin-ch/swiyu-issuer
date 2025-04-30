/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.service;

import ch.admin.bj.swiyu.issuer.oid4vci.api.CredentialEnvelopeDto;
import ch.admin.bj.swiyu.issuer.oid4vci.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.oid4vci.common.exception.CredentialException;
import ch.admin.bj.swiyu.issuer.oid4vci.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.credentialoffer.VerifiableCredentialStatusFactory;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.credentialoffer.VerifiableCredentialStatusReference;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.credentialrequest.CredentialResponseEncryption;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.credentialrequest.encryption.CredentialResponseEncryptor;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.credentialrequest.holderbinding.DidJwk;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.metadata.CredentialConfiguration;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.metadata.IssuerMetadataTechnical;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSSigner;
import lombok.Getter;
import org.springframework.http.MediaType;

import java.util.*;

import static ch.admin.bj.swiyu.issuer.oid4vci.common.exception.CredentialRequestError.INVALID_CREDENTIAL_REQUEST;

@Getter
public abstract class CredentialBuilder {
    private final ApplicationProperties applicationProperties;
    private final IssuerMetadataTechnical issuerMetadata;
    private final DataIntegrityService dataIntegrityService;
    private final JWSSigner signer;
    private CredentialResponseEncryptor credentialResponseEncryptor;
    private CredentialOffer credentialOffer;
    private CredentialConfiguration credentialConfiguration;
    private Optional<DidJwk> holderBinding;
    private List<String> metadataCredentialsSupportedIds;

    CredentialBuilder(ApplicationProperties applicationProperties, IssuerMetadataTechnical issuerMetadata, DataIntegrityService dataIntegrityService, JWSSigner signer) {
        this.applicationProperties = applicationProperties;
        this.issuerMetadata = issuerMetadata;
        this.dataIntegrityService = dataIntegrityService;
        this.holderBinding = Optional.empty();
        this.signer = signer;
    }

    public CredentialBuilder credentialOffer(CredentialOffer credentialOffer) {
        this.credentialOffer = credentialOffer;
        this.credentialConfiguration = getOfferCredentialConfiguration(credentialOffer);
        return this;
    }

    public CredentialBuilder credentialResponseEncryption(CredentialResponseEncryption credentialResponseEncryption) {
        this.credentialResponseEncryptor = new CredentialResponseEncryptor(issuerMetadata.getResponseEncryption(), credentialResponseEncryption);
        return this;
    }

    public CredentialEnvelopeDto buildCredential() {
        var credential = getCredential();
        var oid4vciCredential = new HashMap<String, String>();
        oid4vciCredential.put("format", this.credentialConfiguration.getFormat());
        oid4vciCredential.put("credential", credential);
        return buildEnvelopeDto(oid4vciCredential);
    }

    public CredentialEnvelopeDto buildEnvelopeDto(Object payload) {
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
        return new CredentialEnvelopeDto(contentType, payloadJson);
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
        return this.dataIntegrityService.getVerifiedOfferData(this.credentialOffer);
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
        return Optional.ofNullable(this.credentialOffer.getOfferStatusSet()).orElse(new HashSet<>()).stream()
                .map(statusFactory::createStatusListReference)
                .map(VerifiableCredentialStatusReference::createVCRepresentation)
                .reduce(statuses, statusFactory::mergeStatus);

    }

    abstract String getCredential();

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