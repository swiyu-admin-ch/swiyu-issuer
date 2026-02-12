package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.common.exception.CredentialException;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.ConfigurationOverride;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusListRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.VerifiableCredentialStatusReference;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.DidJwk;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.jwssignatureservice.factory.strategy.KeyStrategyException;
import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.authlete.sd.SDObjectBuilder;
import com.nimbusds.jose.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.Nullable;
import lombok.extern.slf4j.Slf4j;

import java.text.ParseException;
import java.time.Instant;
import java.util.*;

import static ch.admin.bj.swiyu.issuer.common.date.TimeUtils.*;
import static ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError.INVALID_PROOF;
import static java.util.Objects.nonNull;

@Slf4j
public class SdJwtCredential extends CredentialBuilder {

    public static final String SD_JWT_FORMAT = "vc+sd-jwt";

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
     * Single element in the Sd-Jwt batch issuance context means it can not be different
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

    private static void addHolderBinding(List<DidJwk> holderPublicKeys, int i, SDObjectBuilder builder) {
        if (holderPublicKeys != null && !holderPublicKeys.isEmpty()) {
            var idx = i;
            if (holderPublicKeys.size() == SINGLE_ELEMENT) {
                // Using the same index for all elements in the batch; should only be used in tests as this would allow linkability
                idx = 0;
            }
            var holderPublicKey = holderPublicKeys.get(idx);
            try {
                // Todo: Refactor this once wallet migration is finished
                var cnf = holderPublicKey.getJWK()
                        .toJSONObject();
                var cnfClaim = new HashMap<>();
                cnfClaim.put("jwk", cnf);
                cnfClaim.putAll(cnf);

                builder.putClaim("cnf", cnfClaim);
            } catch (ParseException e) {
                throw new Oid4vcException(
                        e,
                        INVALID_PROOF,
                        String.format("Failed expand holder binding %s to cnf", holderPublicKey.getDidJwk())
                );
            }
        }
    }

    /**
     * Issues one or a batch of SD-JWT credentials.
     * Batch size as defined in issuer metadata.
     * Validates alignment of holder keys and status references before issuing.
     *
     * @param holderPublicKeys the holders public keys that will be bound to the created credential jwts
     * @return a list of serialized SD-JWTs
     */
    @Override
    public List<String> getCredential(@Nullable List<DidJwk> holderPublicKeys) {
        var statusReferences = getStatusReferences();
        var batchSize = getIssuerMetadata().getIssuanceBatchSize();
        if (!getStatusFactory().isCompatibleStatusReferencesToBatchSize(statusReferences, batchSize)) {
            throw new IllegalStateException(
                    "Batch size and status references do not match anymore. Cannot issue credential");
        }

        var override = getCredentialOffer().getConfigurationOverride();

        var sdjwts = new ArrayList<String>(batchSize);
        for (int i = 0; i < batchSize; i++) {
            SDObjectBuilder builder = new SDObjectBuilder();

            addTechnicalData(builder, override);
            List<Disclosure> disclosures = prepareDisclosures(builder);

            addHolderBinding(holderPublicKeys, i, builder);
            addStatusReferences(statusReferences, i, builder);
            sdjwts.add(createSignedSDJWT(override, builder, disclosures));
        }
        return Collections.unmodifiableList(sdjwts);
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

    private void addTechnicalData(SDObjectBuilder builder, ConfigurationOverride override) {
        // Mandatory claims or claims which always need to be disclosed according to SD-JWT VC specification
        builder.putClaim("iss", override.issuerDidOrDefault(getApplicationProperties().getIssuerId()));
        // Get first entry because we expect the list to only contain one item
        var metadataId = getMetadataCredentialsSupportedIds().getFirst();
        builder.putClaim("vct",
                getIssuerMetadata().getCredentialConfigurationById(metadataId)
                        .getVct());
        // if we have a vct#integrity, add it
        var credentialMetadata = getCredentialOffer().getCredentialMetadata();
        if (nonNull(credentialMetadata)) {
            Optional.ofNullable(credentialMetadata.vctIntegrity())
                    .ifPresent(o -> builder.putClaim("vct#integrity", o));
            Optional.ofNullable(credentialMetadata.vctMetadataUri())
                    .ifPresent(o -> builder.putClaim("vct_metadata_uri", o));
            Optional.ofNullable(credentialMetadata.vctMetadataUriIntegrity())
                    .ifPresent(o -> builder.putClaim("vct_metadata_uri#integrity", o));
        }
        builder.putClaim("iat", instantToRoundedUnixTimestamp(Instant.now()));

        // optional field -> only added when set
        if (nonNull(getCredentialOffer().getCredentialValidFrom())) {
            builder.putClaim("nbf", instantToRoundedUnixTimestamp(getCredentialOffer().getCredentialValidFrom()));
        }

        // optional field -> only added when set
        if (nonNull(getCredentialOffer().getCredentialValidUntil())) {
            builder.putClaim("exp", instantToRoundedUnixTimestamp(getCredentialOffer().getCredentialValidUntil()));
        }
    }

    /**
     * Prepares the discosures, the actual business data of the sd-jwt
     *
     * @return list of the disclosures possible
     */
    private List<Disclosure> prepareDisclosures(SDObjectBuilder builder) {
        // Optional claims as disclosures
        // Code below follows example from https://github.com/authlete/sd-jwt?tab=readme-ov-file#credential-jwt
        List<Disclosure> disclosures = new ArrayList<>();

        // https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html#section-3.2.2.2
        for (var entry : getOfferData().entrySet()) {
            // Check if it's a protected claim
            if (SDJWT_PROTECTED_CLAIMS.contains(entry.getKey())) {
                // We only log the issue and do not add the claim.
                log.warn(
                        "Upstream application tried to override protected claim {} in credential offer {}. Original value has been retained",
                        entry.getKey(),
                        getCredentialOffer().getId());
            }
            // Only process entries that are not protected claims and not null
            else if (entry.getValue() != null) {
                // TODO: EID-1782; Handle mandatory subject fields using issuer metadata
                Disclosure dis = new Disclosure(entry.getKey(), entry.getValue());
                disclosures.add(dis);
                builder.putSDClaim(dis);
            }
            // Skip null values without any action
        }
        return disclosures;
    }

    private void addStatusReferences(Map<String, List<VerifiableCredentialStatusReference>> statusReferences,
                                     int i,
                                     SDObjectBuilder builder) {
        //Add all status entries (if any)
        for (Map.Entry<String, Object> statusEntry : getStatusReferenceSlice(statusReferences, i).entrySet()) {
            builder.putClaim(statusEntry.getKey(), statusEntry.getValue());
        }
    }

    private String createSignedSDJWT(ConfigurationOverride override,
                                     SDObjectBuilder builder,
                                     List<Disclosure> disclosures) {
        try {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType(SD_JWT_FORMAT))
                    .keyID(override.verificationMethodOrDefault(sdjwtProperties.getVerificationMethod()))
                    .customParam("ver", sdjwtProperties.getVersion())
                    .build();
            JWTClaimsSet claimsSet = JWTClaimsSet.parse(builder.build(true));
            SignedJWT jwt = new SignedJWT(header, claimsSet);

            jwt.sign(this.createSigner());

            return new SDJWT(jwt.serialize(), disclosures).toString();
        } catch (ParseException | JOSEException e) {
            throw new CredentialException(e);
        }
    }

    /**
     * Build status JSON for a single slice
     */
    private Map<String, Object> getStatusReferenceSlice(Map<String, List<VerifiableCredentialStatusReference>> statusReferences,
                                                        int index) {
        return statusReferences.values()
                .stream()
                // Get batch element
                .map(references -> {
                    if (references.size() == SINGLE_ELEMENT) {
                        return references.getFirst();
                    }
                    return references.get(index);
                })
                // create JSON
                .map(VerifiableCredentialStatusReference::createVCRepresentation)
                // Merge JSONs into one
                .reduce((acc, elem) -> getStatusFactory().mergeStatus(acc, elem))
                .orElse(new HashMap<>());

    }
}