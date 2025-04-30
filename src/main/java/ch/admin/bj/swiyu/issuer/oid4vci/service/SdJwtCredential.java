/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.service;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static ch.admin.bj.swiyu.issuer.oid4vci.common.exception.CredentialRequestError.INVALID_PROOF;
import static ch.admin.bj.swiyu.issuer.oid4vci.common.utils.TimeUtils.getUnixTimeStamp;
import static ch.admin.bj.swiyu.issuer.oid4vci.common.utils.TimeUtils.instantToUnixTimestamp;
import static java.util.Objects.nonNull;

import ch.admin.bj.swiyu.issuer.oid4vci.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.oid4vci.common.config.SdjwtProperties;
import ch.admin.bj.swiyu.issuer.oid4vci.common.exception.CredentialException;
import ch.admin.bj.swiyu.issuer.oid4vci.common.exception.Oid4vcException;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.metadata.IssuerMetadataTechnical;
import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.authlete.sd.SDObjectBuilder;
import com.nimbusds.jose.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class SdJwtCredential extends CredentialBuilder {

    private final SdjwtProperties sdjwtProperties;


    public SdJwtCredential(ApplicationProperties applicationProperties, IssuerMetadataTechnical issuerMetadata, DataIntegrityService dataIntegrityService, SdjwtProperties sdjwtProperties, JWSSigner signer) {
        super(applicationProperties, issuerMetadata, dataIntegrityService, signer);
        this.sdjwtProperties = sdjwtProperties;
    }

    @Override
    public String getCredential() {

        SDObjectBuilder builder = new SDObjectBuilder();

        // Mandatory claims or claims which always need to be disclosed according to SD-JWT VC specification
        builder.putClaim("iss", getApplicationProperties().getIssuerId());
        // Get first entry because we expect the list to only contain one item
        var metadataId = getMetadataCredentialsSupportedIds().getFirst();
        builder.putClaim("vct", getIssuerMetadata().getCredentialConfigurationById(metadataId).getVct());
        // if we have a vct#integrity, add it
        Optional.ofNullable(getCredentialOffer().getCredentialMetadata().get("vct#integrity")).ifPresent(o -> builder.putClaim("vct#integrity", o));
        builder.putClaim("iat", getUnixTimeStamp());

        // optional field -> only added when set
        if (nonNull(getCredentialOffer().getCredentialValidFrom())) {
            builder.putClaim("nbf", instantToUnixTimestamp(getCredentialOffer().getCredentialValidFrom()));
        }

        // optional field -> only added when set
        if (nonNull(getCredentialOffer().getCredentialValidUntil())) {
            builder.putClaim("exp", instantToUnixTimestamp(getCredentialOffer().getCredentialValidUntil()));
        }

        getHolderBinding().ifPresent(didJwk -> {
            try {
                builder.putClaim("cnf", didJwk.getJWK().toJSONObject());
            } catch (ParseException e) {
                throw new Oid4vcException(
                        e,
                        INVALID_PROOF,
                        String.format("Failed expand holder binding %s to cnf", didJwk.getDidJwk())
                );
            }
        });

        //Add all status entries (if any)
        for (Map.Entry<String, Object> statusEntry : getStatusReferences().entrySet()) {
            builder.putClaim(statusEntry.getKey(), statusEntry.getValue());
        }
        // https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html#section-3.2.2.2
        // Registered JWT claims MUST be included not as always disclosed
        // sub & iat may explicitly be selectively disclosed
        var protectedClaims = List.of("iss", "nbf", "exp", "iat", "cnf", "vct", "status");


        // Optional claims as disclosures
        // Code below follows example from https://github.com/authlete/sd-jwt?tab=readme-ov-file#credential-jwt
        List<Disclosure> disclosures = new ArrayList<>();
        for (var entry : getOfferData().entrySet()) {
            if (protectedClaims.contains(entry.getKey())) {
                // We only log the issue and do not add the claim.
                log.warn("Upstream application tried to override protected claim {} in credential offer {}. Original value has been retained",
                        entry.getKey(), getCredentialOffer().getId());
                continue;
            }
            if (entry.getValue() == null) {
                // 20250314 - Despite claiming it works, authlete will crash with a nullpointer when given a null value
                continue;
            }
            // TODO: EID-1782; Handle mandatory subject fields using issuer metadata
            Disclosure dis = new Disclosure(entry.getKey(), entry.getValue());
            disclosures.add(dis);
            builder.putSDClaim(dis);
        }

        try {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType("vc+sd-jwt"))
                    .keyID(sdjwtProperties.getVerificationMethod())
                    .customParam("ver", sdjwtProperties.getVersion())
                    .build();
            JWTClaimsSet claimsSet = JWTClaimsSet.parse(builder.build(true));
            SignedJWT jwt = new SignedJWT(header, claimsSet);

            jwt.sign(this.getSigner());

            return new SDJWT(jwt.serialize(), disclosures).toString();
        } catch (ParseException | JOSEException e) {
            throw new CredentialException(e);
        }
    }
}
