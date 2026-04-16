package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.common.exception.CredentialException;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.common.profile.SwissProfileVersions;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.ConfigurationOverride;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusListRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.VerifiableCredentialStatusReference;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.HolderKeyBinding;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialConfiguration;
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

    private static void addHolderBinding(List<HolderKeyBinding> holderPublicKeys, int i, SDObjectBuilder builder) {
        if (holderPublicKeys != null && !holderPublicKeys.isEmpty()) {
            var idx = i;
            if (holderPublicKeys.size() == SINGLE_ELEMENT) {
                // Using the same index for all elements in the batch; should only be used in
                // tests as this would allow linkability
                idx = 0;
            }
            var holderPublicKey = holderPublicKeys.get(idx);
            try {
                var cnf = holderPublicKey.getJWK()
                        .toJSONObject();
                var cnfClaim = new HashMap<>();
                cnfClaim.put("jwk", cnf);
                builder.putClaim("cnf", cnfClaim);
            } catch (ParseException e) {
                throw new Oid4vcException(
                        e,
                        INVALID_PROOF,
                        "Failed to expand holder binding into cnf",
                        Map.of(
                                "holderKeyIndex", idx,
                                "jwk", holderPublicKey.holderKeyJson()));
            }
        }
    }

    private static String createSDJWT(List<Disclosure> disclosures, SignedJWT jwt) {
        return new SDJWT(jwt.serialize(), disclosures).toString();
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
        for (int i = 0; i < batchSize; i++) {
            Map<String, Object> alwaysDisclosedData = prepareAlwaysDisclosedData(credentialConfiguration, override);
            Map<String, Object> selectivelyDisclosableData = prepareSelectivelyDisclosableData(credentialConfiguration, override);
            final SDObjectBuilder builder = new SDObjectBuilder();
            putAlwaysDisclosedData(builder, alwaysDisclosedData);
            final List<Disclosure> disclosures = putSelectivelyDiscloseableData(builder, selectivelyDisclosableData);

            addHolderBinding(holderPublicKeys, i, builder);
            usedCredentialStatusReferences.addAll(addStatusReferences(statusReferences, i, builder));
            SignedJWT jwt = createSignedJWT(override, builder);
            // Collect hashes of the VCs as way for issuer to be able to trace misused VCs
            vcHashes.add(jwt.getSignature().toString());
            sdjwts.add(createSDJWT(disclosures, jwt));
        }
        // Only save hashes
        if (getApplicationProperties().isEnableVcHashStorage()) {
            getCredentialOffer().setVcHashes(vcHashes);
        }

        freeUnusedStatusReferences(usedCredentialStatusReferences);

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

    /**
     * Add the selectively discloseable data to the SD-JWT and prepare the discosures
     *
     * @return list of the disclosures
     */
    protected List<Disclosure> putSelectivelyDiscloseableData(SDObjectBuilder builder, Map<String, Object> selectivelyDiscloseableData) {
        // Optional claims as disclosures
        // Code below follows example from
        // https://github.com/authlete/sd-jwt?tab=readme-ov-file#credential-jwt
        List<Disclosure> disclosures = new ArrayList<>();
        List<Disclosure> embedded = new ArrayList<>();

        // https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html#section-3.2.2.2

        // If recursive disclosure is enabled, traverse nested objects and build
        // disclosures recursively
        // so object properties become embedded SD claims; otherwise use the
        // non-recursive handler.
        if (Boolean.TRUE.equals(getApplicationProperties().isRecursiveDisclosureEnabled())) {
            handleClaimsRecursive(builder, disclosures, selectivelyDiscloseableData, embedded);
        } else {
            handleClaims(builder, disclosures, selectivelyDiscloseableData, embedded);
        }
        embedded.forEach(builder::putSDClaim);

        return disclosures;
    }

    private void putAlwaysDisclosedData(SDObjectBuilder builder, Map<String, Object> alwaysDisclosedData) {
        alwaysDisclosedData.entrySet().forEach(e -> builder.putClaim(e.getKey(), e.getValue()));
    }

    private List<VerifiableCredentialStatusReference> addStatusReferences(
            Map<String, List<VerifiableCredentialStatusReference>> statusReferences,
            int index,
            SDObjectBuilder builder) {

        var status = statusReferences.values()
                .stream()
                // Get batch element
                .map(references -> {
                    if (references.size() == SINGLE_ELEMENT) {
                        return references.getFirst();
                    }
                    return references.get(index);
                }).toList();

        getStatusReferenceSlice(status)
                .forEach(builder::putClaim);

        return status;
    }

    /**
     * Create a SignedJWT
     *
     * @param override Override value for signing key
     * @param builder  Selective Disclosure Objects (Hashes or always disclosed
     *                 objects) to be included in the claims of the JWT
     * @return JWT Signed with the key provided in the Configuration Override or by
     *         default key
     */
    private SignedJWT createSignedJWT(ConfigurationOverride override,
                                      SDObjectBuilder builder) {
        try {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType(SD_JWT_FORMAT))
                    .keyID(override.verificationMethodOrDefault(sdjwtProperties.getVerificationMethod()))
                    .customParam(SwissProfileVersions.PROFILE_VERSION_PARAM, SwissProfileVersions.VC_PROFILE_VERSION)
                    .build();
            JWTClaimsSet claimsSet = JWTClaimsSet.parse(builder.build(true));
            SignedJWT jwt = new SignedJWT(header, claimsSet);
            jwt.sign(this.createSigner());
            return jwt;
        } catch (ParseException | JOSEException e) {
            throw new CredentialException(e);
        }
    }

    protected List<Disclosure> handleClaimsRecursive(SDObjectBuilder builder,
                                                     List<Disclosure> disclosures,
                                                     Map<String, Object> offerData,
                                                     List<Disclosure> disclosuresForVCObjectProperties) {

        offerData.forEach((entryKey, entryValue) -> {

            if (validateOfferData(entryKey, entryValue))
                return;

            switch (entryValue) {
                case Map<?, ?> mapValue when mapValue instanceof Map<?, ?> m &&
                        m.keySet().stream().allMatch(String.class::isInstance) ->
                        handleNestedClaimRecursive(entryKey, (Map<String, Object>) m, disclosures,
                                disclosuresForVCObjectProperties);
                case Collection<?> collectionValue ->
                        handleListDisclosures(builder, Map.entry(entryKey, entryValue), collectionValue, disclosures);
                default ->
                        handleLeafClaim(Map.entry(entryKey, entryValue), disclosures, disclosuresForVCObjectProperties,
                                builder);
            }
        });

        return disclosuresForVCObjectProperties;
    }

    protected void handleClaims(SDObjectBuilder builder,
                                List<Disclosure> disclosures,
                                Map<String, Object> offerData,
                                List<Disclosure> disclosuresForVCObjectProperties) {

        offerData.forEach((entryKey, entryValue) -> {

            if (validateOfferData(entryKey, entryValue))
                return;

            if (entryValue instanceof Collection<?> collectionValue) {
                var disc = collectionValue.stream().map(item -> {
                    var dis = new Disclosure(item);
                    disclosures.add(dis);
                    return dis.toArrayElement();
                }).toList();

                builder.putClaim(entryKey, disc);
            } else {
                handleLeafClaim(Map.entry(entryKey, entryValue), disclosures, disclosuresForVCObjectProperties,
                        builder);
            }
        });
    }

    private boolean validateOfferData(String entryKey, Object entryValue) {
        if (SDJWT_PROTECTED_CLAIMS.contains(entryKey)) {
            // We only log the issue and do not add the claim.
            log.warn(
                    "Upstream application tried to override protected claim {} in credential offer {}. Original value has been retained",
                    entryKey,
                    getCredentialOffer().getId());
            return true;
        }

        if (entryValue == null) {
            log.warn(
                    "Null value for claim {} in credential offer {} has been ignored and will not be included in the credential",
                    entryKey,
                    getCredentialOffer().getId());
            return true;
        }
        return false;
    }

    private void handleNestedClaimRecursive(String entryKey,
                                            Map<String, Object> mapValue,
                                            List<Disclosure> disclosures,
                                            List<Disclosure> disclosuresForVCObjectProperties) {

        // Create a new builder for the nested map to build its disclosures
        var nestedBuilder = new SDObjectBuilder();
        // throw away list for recursive calls, we only need the
        // disclosuresForVCObjectPropertie of the top level in recursive case (as these
        // cases should not be added as sd claims)
        var ignoredDisclosuresForVCObjectProperties = new ArrayList<Disclosure>();

        // Recursive call for nested maps
        handleClaimsRecursive(nestedBuilder, disclosures, mapValue, ignoredDisclosuresForVCObjectProperties);

        // Create new Disclosure for the nested map and add it to the disclosures list
        // and the parent builder
        var nestedDigest = new Disclosure(entryKey, nestedBuilder.build());

        disclosures.add(nestedDigest);
        disclosuresForVCObjectProperties.add(nestedDigest);
    }

    /**
     * Build status JSON for a single slice
     */
    private Map<String, Object> getStatusReferenceSlice(List<VerifiableCredentialStatusReference> statusReferences) {
        return statusReferences
                .stream()
                // Get batch element
                .map(VerifiableCredentialStatusReference::createVCRepresentation)
                // Merge JSONs into one
                .reduce((acc, elem) -> getStatusFactory().mergeStatus(acc, elem))
                .orElse(new HashMap<>());
    }

    private void handleListDisclosures(SDObjectBuilder builder,
                                       Map.Entry<String, Object> entry,
                                       Collection<?> collectionValue,
                                       List<Disclosure> disclosures) {
        var disc = collectionValue.stream().map(item -> {
            var dis = new Disclosure(item);
            disclosures.add(dis);
            return dis.toArrayElement();
        }).toList();

        if (Boolean.TRUE.equals(getApplicationProperties().isRecursiveDisclosureEnabled())) {

            // for strings
            var recDisclosure = new Disclosure(entry.getKey(), disc);
            disclosures.add(recDisclosure);
            builder.putSDClaim(recDisclosure);
        } else {
            builder.putClaim(entry.getKey(), disc);
        }
    }

    private void handleLeafClaim(Map.Entry<String, Object> entry, List<Disclosure> disclosures,
                                 List<Disclosure> disclosuresForVCObjectProperties, SDObjectBuilder builder) {
        var disclosure = new Disclosure(entry.getKey(), entry.getValue());
        disclosures.add(disclosure);
        builder.putSDClaim(disclosure);
        disclosuresForVCObjectProperties.add(disclosure);
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


    private Map<String, Object> prepareAlwaysDisclosedData(CredentialConfiguration credentailConfiguration, ConfigurationOverride override) {
        Map<String, Object> alwaysDisclosedData = new HashMap<>();
        // Mandatory claims or claims which always need to be disclosed according to
        // SD-JWT VC specification
        alwaysDisclosedData.put("iss", override.issuerDidOrDefault(getApplicationProperties().getIssuerId()));
        alwaysDisclosedData.put("vct", credentailConfiguration.getVct());
        // Optional vct addons
        Optional.ofNullable(credentailConfiguration.getVctMetadataUri())
                .ifPresent(o -> alwaysDisclosedData.put("vct_metadata_uri", o));
        Optional.ofNullable(credentailConfiguration.getVctMetadataUriIntegrity())
                .ifPresent(o -> alwaysDisclosedData.put("vct_metadata_uri#integrity", o));
        // if we have dynamically overriden vct#integrity or such, add it
        var credentialMetadata = getCredentialOffer().getCredentialMetadata();
        if (nonNull(credentialMetadata)) {
            Optional.ofNullable(credentialMetadata.vctIntegrity())
                    .ifPresent(o -> alwaysDisclosedData.put("vct#integrity", o));
            Optional.ofNullable(credentialMetadata.vctMetadataUri())
                    .ifPresent(o -> alwaysDisclosedData.put("vct_metadata_uri", o));
            Optional.ofNullable(credentialMetadata.vctMetadataUriIntegrity())
                    .ifPresent(o -> alwaysDisclosedData.put("vct_metadata_uri#integrity", o));
        }
        // subtracting 1 day, as instantToRoundedUnixTimestamp rounds up to the end of
        // the day
        alwaysDisclosedData.put("iat", instantToRoundedDownUnixTimestamp(Instant.now()));

        // optional field -> only added when set
        if (nonNull(getCredentialOffer().getCredentialValidFrom())) {
            alwaysDisclosedData.put("nbf", instantToRoundedDownUnixTimestamp(getCredentialOffer().getCredentialValidFrom()));
        }

        // optional field -> only added when set
        if (nonNull(getCredentialOffer().getCredentialValidUntil())) {
            alwaysDisclosedData.put("exp", instantToRoundedUpUnixTimestamp(getCredentialOffer().getCredentialValidUntil()));
        }
        return alwaysDisclosedData;
    }

    private Map<String, Object> prepareSelectivelyDisclosableData(CredentialConfiguration credentailConfiguration, ConfigurationOverride override) {
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