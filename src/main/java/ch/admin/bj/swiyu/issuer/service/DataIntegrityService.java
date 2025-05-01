/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
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
import com.nimbusds.jwt.SignedJWT;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
@AllArgsConstructor
@Slf4j
public class DataIntegrityService {
    private final ApplicationProperties applicationProperties;


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
    public Map<String, Object> getVerifiedOfferData(CredentialOffer offer) {
        Map<String, Object> offerData = offer.getOfferData();
        if (offerData == null || !offerData.containsKey("data")) {
            log.error(String.format("Issuer Management Error - Offer %s lacks any offer data", offer.getId()));
            throw new CredentialException("No offer data found");
        } else if (offerData.containsKey("data_integrity")) {
            // Data Integrity Checks
            try {
                SignedJWT dataIntegrityJWT = SignedJWT.parse((String) offerData.get("data"));
                JWSHeader jwtHeader = dataIntegrityJWT.getHeader();
                JWK matchingKey = applicationProperties.getDataIntegrityKeySet().getKeyByKeyId(jwtHeader.getKeyID());
                KeyType kty = matchingKey.getKeyType();

                if (!dataIntegrityJWT.verify(buildJWSVerifier(kty, matchingKey))) {
                    log.error(String.format("Data Integrity of offer %s could not be verified with key %s", offer.getId(), matchingKey.toJSONString()));
                    throw new CredentialException("Data Integrity of offer could not be verified");
                }
                // Return Verified Data
                return dataIntegrityJWT.getJWTClaimsSet().toJSONObject();
            } catch (Exception e) {
                log.error(String.format("Failed setting up Data Integrity check of offer %s with JWKS %s - caused by ", offer.getId(), applicationProperties.getDataIntegrityJwks()), e.getMessage());
                throw new CredentialException(e);
            }
        }
        // Just return the data if its not data integrity protected from the issuer management
        try {
            return new ObjectMapper().readValue((String) offerData.get("data"), HashMap.class);
        } catch (JsonProcessingException e) {
            log.error(String.format("Could not load offer data of offer %s", offer.getId()));
            throw new CredentialException("Failed to parse offer data", e);
        }
    }
}
