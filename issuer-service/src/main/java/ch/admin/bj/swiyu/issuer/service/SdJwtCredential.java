package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.common.exception.CredentialException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.ConfigurationOverride;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusListRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.VerifiableCredentialStatusReference;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.HolderKeyBinding;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialConfiguration;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.jwssignatureservice.factory.strategy.KeyStrategyException;
import ch.admin.bj.swiyu.sdjwtbuilder.SdJwtVcBuilder;
import ch.admin.bj.swiyu.sdjwtbuilder.SdJwtVcClaim;
import ch.admin.bj.swiyu.sdjwtbuilder.TimeConfiguration;
import ch.admin.bj.swiyu.sdjwtbuilder.exception.SdJwtBuilderException;
import ch.admin.bj.swiyu.sdjwtbuilder.SdJwtVcBuilder.CreatedSdJwtVc;
import ch.admin.bj.swiyu.statuslist.dto.TokenStatusListReferenceDto.TokenStatusListStatusListReference;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.JWK;
import jakarta.annotation.Nullable;
import lombok.extern.slf4j.Slf4j;

import java.text.ParseException;
import java.time.Instant;
import java.util.*;


import static java.util.Objects.nonNull;

@Slf4j
public class SdJwtCredential extends CredentialBuilder {

    public static final String SD_JWT_FORMAT = "dc+sd-jwt";

    public static final List<String> SDJWT_PROTECTED_CLAIMS = List.of("sub",
            "iss",
            "nbf",
            "exp",
            "iat",
            "cnf",
            "vct",
            "status",
            "_sd",
            "_sd_alg",
            "sd_hash",
            "...");
    /**
     * Single element in the Sd-Jwt batch issuance context means it can not be
     * different
     * in slices and will be reused for each element in the batch.
     * Be aware that this can potentially lead to linkability
     */
    public static final int SINGLE_ELEMENT = 1;

    private final SdjwtProperties sdjwtProperties;

    public SdJwtCredential(
            ApplicationProperties applicationProperties,
            IssuerMetadata issuerMetadata,
            DataIntegrityService dataIntegrityService,
            SdjwtProperties sdjwtProperties,
            JwsSignatureFacade jwsSignatureFacade,
            StatusListRepository statusListRepository,
            CredentialOfferStatusRepository credentialOfferStatusRepository) {
        super(applicationProperties,
                issuerMetadata,
                dataIntegrityService,
                statusListRepository,
                jwsSignatureFacade,
                credentialOfferStatusRepository);
        this.sdjwtProperties = sdjwtProperties;
    }

    /**
     * Issues one or a batch of SD-JWT credentials.
     * Batch size is determined by the number of holder public keys (if provided),
     * otherwise by the issuer metadata configuration.
     * Validates alignment of holder keys and status references before issuing.
     *
     * @param holderPublicKeys the holders public keys that will be bound to the
     *                         created credential jwts
     * @return a list of serialized SD-JWTs
     */
    @Override
    public List<String> getCredential(@Nullable List<HolderKeyBinding> holderPublicKeys) {
        var statusReferences = getStatusReferences();
        var batchSize = calculateBatchSize(holderPublicKeys);
        if (!getStatusFactory().isCompatibleStatusReferencesToBatchSize(statusReferences, getIssuerMetadata(),
                batchSize)) {
            throw new IllegalStateException(
                    "Batch size and status references do not match anymore. Cannot issue credential");
        }
        final ConfigurationOverride override = getCredentialOffer().getConfigurationOverride();
        final var sdjwts = new ArrayList<String>(batchSize);
        var vcHashes = new ArrayList<String>(batchSize);
        List<VerifiableCredentialStatusReference> usedCredentialStatusReferences = new ArrayList<>(batchSize);
        // Get first entry because we expect the list to only contain one item
        final var metadataId = getMetadataCredentialsSupportedIds().getFirst();
        final var credentialConfiguration = getIssuerMetadata().getCredentialConfigurationById(metadataId);
        
        
        
        SdJwtVcBuilder vcBuilder;
        try {
            vcBuilder = SdJwtVcBuilder.createBuilder(
                override.verificationMethodOrDefault(sdjwtProperties.getVerificationMethod()), 
                prepareAlwaysDisclosedData(credentialConfiguration, override),
                prepareSelectivelyDisclosableData(credentialConfiguration),
                prepareTimeConfiguration(),
                this.createSigner());
                
                for (int i = 0; i < batchSize; i++) {
                    Optional<VerifiableCredentialStatusReference> statusReference = reserveStatusReferences(statusReferences, i);
                    statusReference.ifPresent(sRef -> usedCredentialStatusReferences.add(sRef));
                    Optional<JWK> holderPublicKey = getHolderPublicKey(i, holderPublicKeys);
                    
                    CreatedSdJwtVc vc = vcBuilder.createSignedSdJwtVc(toLibraryTokenStatusListReference(statusReference), holderPublicKey);
                    vcHashes.add(vc.vcHash());
                    sdjwts.add(vc.serializedSdJwt());
                }
            } catch (SdJwtBuilderException e) {
                throw new CredentialException("Failed to build the SD-JWT VC", e);
            }
        // Only save hashes if needed
        if (getApplicationProperties().isEnableVcHashStorage()) {
            getCredentialOffer().setVcHashes(vcHashes);
        }
        freeUnusedStatusReferences(usedCredentialStatusReferences);

        return Collections.unmodifiableList(sdjwts);
    }

    private Optional<JWK> getHolderPublicKey(int i, List<HolderKeyBinding> holderPublicKeys) {
        if (holderPublicKeys == null || holderPublicKeys.isEmpty()) {
            return Optional.empty();
        }
        try {
            return Optional.of(holderPublicKeys.get(i).getJWK());
        } catch (ParseException e) {
            throw new CredentialException("Holder Public Key cannot be parsed", e);
        }
    }

    @Override
    JWSSigner createSigner() {
        var override = this.getCredentialOffer()
                .getConfigurationOverride();
        try {
            return getJwsSignatureFacade().createSigner(
                    sdjwtProperties,
                    override.keyId(),
                    override.keyPin());
        } catch (KeyStrategyException e) {
            throw new CredentialException(e);
        }
    }


    private Optional<TokenStatusListStatusListReference> toLibraryTokenStatusListReference(Optional<VerifiableCredentialStatusReference> reference) {
        if (reference == null || reference.isEmpty()) {
            return Optional.empty();
        }
        VerifiableCredentialStatusReference ref = reference.get();
        var libRef = new TokenStatusListStatusListReference();
        libRef.setIndex(ref.getIndex());
        libRef.setUri(ref.getIdentifier());
        return Optional.of(libRef);
    }


    private Optional<VerifiableCredentialStatusReference> reserveStatusReferences(
            List<VerifiableCredentialStatusReference> statusReferences,
            int index) {

        if(statusReferences.isEmpty()) {
            return Optional.empty();
        }
        if(statusReferences.size() == SINGLE_ELEMENT) {
            return Optional.of(statusReferences.getFirst());
        }
        return Optional.of(statusReferences.get(index));
    }


    /**
     * Calculate batch size by the number of proofs provided by the holder or batch
     * size defined in issuer metadata
     *
     * @param holderPublicKeys the holders public keys that will be bound to the
     *                         created credential jwts
     * @return batch size to issue
     */
    private int calculateBatchSize(@Nullable List<HolderKeyBinding> holderPublicKeys) {
        if (!getIssuerMetadata().isBatchIssuanceAllowed()) {
            return 1;
        }
        return holderPublicKeys != null && !holderPublicKeys.isEmpty()
                ? holderPublicKeys.size()
                : getIssuerMetadata().getIssuanceBatchSize();
    }


    private Map<SdJwtVcClaim, Object> prepareAlwaysDisclosedData(CredentialConfiguration credentailConfiguration, ConfigurationOverride override) {
        Map<SdJwtVcClaim, Object> alwaysDisclosedData = new HashMap<>();
        // Mandatory claims or claims which always need to be disclosed according to
        // SD-JWT VC specification
        alwaysDisclosedData.put(SdJwtVcClaim.VCT, credentailConfiguration.getVct());
        // In swiss profile 1.0 Issuer not required / used for verification anymore. For clarity it is added.
        alwaysDisclosedData.put(SdJwtVcClaim.ISSUER, override.issuerDidOrDefault(getApplicationProperties().getIssuerId()));

        // Optional vct addons
        Optional.ofNullable(credentailConfiguration.getVctMetadataUri())
                .ifPresent(o -> alwaysDisclosedData.put(SdJwtVcClaim.VCT_METADATA_URI, o));
        Optional.ofNullable(credentailConfiguration.getVctMetadataUriIntegrity())
                .ifPresent(o -> alwaysDisclosedData.put(SdJwtVcClaim.VCT_METADATA_URI_INTEGRITY, o));
        var credentialMetadata = getCredentialOffer().getCredentialMetadata();
        if (nonNull(credentialMetadata)) {
            Optional.ofNullable(credentialMetadata.vctMetadataUri())
                    .ifPresent(o -> alwaysDisclosedData.put(SdJwtVcClaim.VCT_METADATA_URI, o));
            Optional.ofNullable(credentialMetadata.vctMetadataUriIntegrity())
                    .ifPresent(o -> alwaysDisclosedData.put(SdJwtVcClaim.VCT_METADATA_URI_INTEGRITY, o));
        }
        return alwaysDisclosedData;
    }

    private TimeConfiguration prepareTimeConfiguration() {
        return TimeConfiguration.builder()
            .issuedAt(Optional.of(Instant.now()))
            .notBefore(Optional.ofNullable(getCredentialOffer().getCredentialValidFrom()))
            .expiry(Optional.ofNullable(getCredentialOffer().getCredentialValidUntil()))
            .build();
        
    }

    private Map<String, Object> prepareSelectivelyDisclosableData(CredentialConfiguration credentailConfiguration) {
        // Custom Data
        Map<String, Object> selectivelyDisclosableData = getOfferData();
        // Extended VCT versioning
        Optional.ofNullable(credentailConfiguration.getVctVersion())
                .ifPresent(o -> selectivelyDisclosableData.put("vct_version", o));
        Optional.ofNullable(credentailConfiguration.getVctSubtype())
                .ifPresent(o -> selectivelyDisclosableData.put("vct_subtype", o));
        Optional.ofNullable(credentailConfiguration.getVctSubtypeVersion())
                .ifPresent(o -> selectivelyDisclosableData.put("vct_subtype_version", o));
        return selectivelyDisclosableData;
    }
}