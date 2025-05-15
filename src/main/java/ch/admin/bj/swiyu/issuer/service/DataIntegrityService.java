/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.common.exception.CredentialException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
@AllArgsConstructor
@Slf4j
public class DataIntegrityService {
    private final ApplicationProperties applicationProperties;
    private final ObjectMapper objectMapper;

    private static JWSVerifier buildJWSVerifier(KeyType kty, JWK key) throws JOSEException {
        if (KeyType.EC.equals(kty)) {
            return new ECDSAVerifier(key.toECKey().toPublicJWK());
        } else if (KeyType.RSA.equals(kty)) {
            return new RSASSAVerifier(key.toRSAKey().toPublicJWK());
        }
        throw new JOSEException("Unsupported Key Type %s".formatted(kty));
    }

    /**
     * Unpacks the credential offer data and returns is as HashMap.
     * If Data integrity checks are available performs these.
     *
     * @return the Offered Credential Subject Data.
     */
    public Map<String, Object> getVerifiedOfferData(Map<String, Object> offerData, UUID offerId) {
        var offerIdentifier = offerId == null ? "" : offerId;
        if (offerData == null || !offerData.containsKey("data")) {
            log.error(String.format("Issuer Management Error - Offer %s lacks any offer data", offerIdentifier));
            throw new BadRequestException("No offer data found");
        } else if (offerData.containsKey("data_integrity")) {
            // Data Integrity Checks
            try {
                SignedJWT dataIntegrityJWT = SignedJWT.parse((String) offerData.get("data"));
                JWSHeader jwtHeader = dataIntegrityJWT.getHeader();
                JWK matchingKey = applicationProperties.getDataIntegrityKeySet().getKeyByKeyId(jwtHeader.getKeyID());

                if (matchingKey == null) {
                    log.error(String.format("Data Integrity of offer %s could not be verified with key %s", offerIdentifier, applicationProperties.getDataIntegrityJwks()));
                    throw new BadRequestException("Data Integrity of offer could not be verified. No matching key found");
                }

                KeyType kty = matchingKey.getKeyType();

                if (!dataIntegrityJWT.verify(buildJWSVerifier(kty, matchingKey))) {
                    log.error(String.format("Data Integrity of offer %s could not be verified with key %s", offerIdentifier, matchingKey.toJSONString()));
                    throw new BadRequestException("Data Integrity of offer could not be verified");
                }
                // Return Verified Data
                return dataIntegrityJWT.getJWTClaimsSet().toJSONObject();
            } catch (Exception e) {
                log.error(String.format("Failed setting up Data Integrity check of offer %s with JWKS %s - caused by ", offerIdentifier, applicationProperties.getDataIntegrityJwks()), e.getMessage());
                throw new BadRequestException(e.getMessage());
            }
        }
        // Just return the data if its not data integrity protected from the issuer management
        try {
            return objectMapper.readValue((String) offerData.get("data"), HashMap.class);
        } catch (JsonProcessingException e) {
            log.error(String.format("Could not load offer data of offer %s", offerIdentifier));
            throw new CredentialException("Failed to parse offer data", e);
        }
    }
}