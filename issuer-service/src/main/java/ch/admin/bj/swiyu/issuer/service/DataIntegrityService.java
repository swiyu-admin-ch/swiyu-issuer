/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.common.exception.CredentialException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jwt.SignedJWT;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
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

    private boolean isDataIntegrityRequired(Map<String, Object> offerData) {
        return offerData.containsKey("data_integrity") || applicationProperties.isDataIntegrityEnforced();
    }

    private Map<String, Object> verifyDataIntegrityJWT(String jwtString, UUID offerId) {
        var offerIdentifier = offerId == null ? "" : offerId;
        try {
            SignedJWT dataIntegrityJWT = SignedJWT.parse(jwtString);
            JWSHeader jwtHeader = dataIntegrityJWT.getHeader();
            JWK matchingKey = applicationProperties.getDataIntegrityKeySet().getKeyByKeyId(jwtHeader.getKeyID());

            if (matchingKey == null) {
                log.error("Data Integrity of offer {} could not be verified with key {}", offerIdentifier, applicationProperties.getDataIntegrityJwks());
                throw new BadRequestException("Data Integrity of offer could not be verified. No matching key found");
            }

            KeyType kty = matchingKey.getKeyType();

            if (!dataIntegrityJWT.verify(buildJWSVerifier(kty, matchingKey))) {
                log.error("Data Integrity of offer {} could not be verified with key {}", offerIdentifier, matchingKey.toJSONString());
                throw new BadRequestException("Data Integrity of offer could not be verified");
            }
            return dataIntegrityJWT.getJWTClaimsSet().toJSONObject();
        } catch (Exception e) {
            log.error("Failed setting up Data Integrity check of offer {} with JWKS {} - caused by {}", offerIdentifier, applicationProperties.getDataIntegrityJwks(), e.getMessage());
            throw new BadRequestException(e.getMessage());
        }
    }

    private Map<String, Object> parseOfferData(String data, UUID offerId) {
        var offerIdentifier = offerId == null ? "" : offerId;
        try {
            return objectMapper.readValue(data, HashMap.class);
        } catch (JsonProcessingException e) {
            log.error("Could not load offer data of offer {}", offerIdentifier);
            throw new CredentialException("Failed to parse offer data", e);
        }
    }

    /**
     * Unpacks the credential offer data and returns is as HashMap.
     * If Data integrity checks are available performs these.
     *
     * @param offerData the data to be verified if needed
     * @param offerId id of the offer used only for logging purposes - nullable
     *
     * @return the Offered Credential Subject Data.
     */
    public Map<String, Object> getVerifiedOfferData(Map<String, Object> offerData, UUID offerId) {
        var offerIdentifier = offerId == null ? "" : offerId;
        if (offerData == null || !offerData.containsKey("data")) {
            log.error("Issuer Management Error - Offer {} lacks any offer data", offerIdentifier);
            throw new BadRequestException("No offer data found");
        }

        String data = (String) offerData.get("data");
        if (isDataIntegrityRequired(offerData)) {
            return verifyDataIntegrityJWT(data, offerId);
        }
        return parseOfferData(data, offerId);
    }
}