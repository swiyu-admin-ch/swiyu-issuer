/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.common.exception.CredentialException;
import ch.admin.bj.swiyu.issuer.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusListRepository;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.DidJwk;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.service.factory.strategy.KeyStrategyException;
import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.authlete.sd.SDObjectBuilder;
import com.nimbusds.jose.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;

import java.text.ParseException;
import java.util.*;

import static ch.admin.bj.swiyu.issuer.common.date.TimeUtils.getUnixTimeStamp;
import static ch.admin.bj.swiyu.issuer.common.date.TimeUtils.instantToUnixTimestamp;
import static ch.admin.bj.swiyu.issuer.common.exception.CredentialRequestError.INVALID_PROOF;
import static java.util.Objects.nonNull;

@Slf4j
public class SdJwtCredential extends CredentialBuilder {

    public static final String SD_JWT_FORMAT = "vc+sd-jwt";

    public static final List<String> SDJWT_PROTECTED_CLAIMS = List.of("sub", "iss", "nbf", "exp", "iat", "cnf", "vct", "status", "_sd", "_sd_alg", "sd_hash", "...");

    private final SdjwtProperties sdjwtProperties;


    public SdJwtCredential(ApplicationProperties applicationProperties, IssuerMetadata issuerMetadata, DataIntegrityService dataIntegrityService, SdjwtProperties sdjwtProperties, SignatureService signatureService, StatusListRepository statusListRepository, CredentialOfferStatusRepository credentialOfferStatusRepository) {
        super(applicationProperties, issuerMetadata, dataIntegrityService, statusListRepository, signatureService, credentialOfferStatusRepository);
        this.sdjwtProperties = sdjwtProperties;
    }

    @Override
    JWSSigner createSigner() {
        var override = this.getCredentialOffer().getConfigurationOverride();
        try {
            return getSignatureService().createSigner(
                    sdjwtProperties,
                    override.keyId(),
                    override.keyPin());
        } catch (KeyStrategyException e) {
            throw new CredentialException(e);
        }
    }

    @Override
    public String getCredential(DidJwk didJwk) {
        var override = getCredentialOffer().getConfigurationOverride();
        SDObjectBuilder builder = new SDObjectBuilder();

        // Mandatory claims or claims which always need to be disclosed according to SD-JWT VC specification
        builder.putClaim("iss", override.issuerDidOrDefault(getApplicationProperties().getIssuerId()));
        // Get first entry because we expect the list to only contain one item
        var metadataId = getMetadataCredentialsSupportedIds().getFirst();
        builder.putClaim("vct", getIssuerMetadata().getCredentialConfigurationById(metadataId).getVct());
        // if we have a vct#integrity, add it
        var credentialMetadata = getCredentialOffer().getCredentialMetadata();
        if (nonNull(credentialMetadata)) {
            Optional.ofNullable(credentialMetadata.vctIntegrity()).ifPresent(o -> builder.putClaim("vct#integrity", o));
            Optional.ofNullable(credentialMetadata.vctMetadataUri()).ifPresent(o -> builder.putClaim("vct_metadata_uri", o));
            Optional.ofNullable(credentialMetadata.vctMetadataUriIntegrity()).ifPresent(o -> builder.putClaim("vct_metadata_uri#integrity", o));
        }
        builder.putClaim("iat", getUnixTimeStamp());

        // optional field -> only added when set
        if (nonNull(getCredentialOffer().getCredentialValidFrom())) {
            builder.putClaim("nbf", instantToUnixTimestamp(getCredentialOffer().getCredentialValidFrom()));
        }

        // optional field -> only added when set
        if (nonNull(getCredentialOffer().getCredentialValidUntil())) {
            builder.putClaim("exp", instantToUnixTimestamp(getCredentialOffer().getCredentialValidUntil()));
        }

        if (didJwk != null) {
            try {
                // Todo: Refactor this once wallet migration is finished
                var cnf = didJwk.getJWK().toJSONObject();
                var cnfClaim = new HashMap<>();
                cnfClaim.put("jwk", cnf);
                cnfClaim.putAll(cnf);

                builder.putClaim("cnf", cnfClaim);
            } catch (ParseException e) {
                throw new Oid4vcException(
                        e,
                        INVALID_PROOF,
                        String.format("Failed expand holder binding %s to cnf", didJwk.getDidJwk())
                );
            }
        }

        //Add all status entries (if any)
        for (Map.Entry<String, Object> statusEntry : getStatusReferences().entrySet()) {
            builder.putClaim(statusEntry.getKey(), statusEntry.getValue());
        }


        // Optional claims as disclosures
        // Code below follows example from https://github.com/authlete/sd-jwt?tab=readme-ov-file#credential-jwt
        List<Disclosure> disclosures = new ArrayList<>();

        // https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html#section-3.2.2.2
        for (var entry : getOfferData().entrySet()) {
            // Check if it's a protected claim
            if (SDJWT_PROTECTED_CLAIMS.contains(entry.getKey())) {
                // We only log the issue and do not add the claim.
                log.warn("Upstream application tried to override protected claim {} in credential offer {}. Original value has been retained",
                        entry.getKey(), getCredentialOffer().getId());
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
}