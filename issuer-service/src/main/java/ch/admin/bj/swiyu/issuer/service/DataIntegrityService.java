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
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Service for verifying and parsing credential offer data.
 * Performs JWT-based data integrity checks if required.
 */
@Service
@AllArgsConstructor
@Slf4j
public class DataIntegrityService {
    private final ApplicationProperties applicationProperties;
    private final ObjectMapper objectMapper;

    /**
     * Checks if data integrity verification is required for the offer.
     * @param offerData offer data map
     * @return true if required
     */
    private boolean isDataIntegrityRequired(Map<String, Object> offerData) {
        if (offerData == null) {
            return applicationProperties.isDataIntegrityEnforced();
        }
        return offerData.containsKey("data_integrity") || applicationProperties.isDataIntegrityEnforced();
    }

    /**
     * Verifies the JWT signature and returns claims as a map.
     * Throws BadRequestException on failure.
     * @param jwtString JWT string
     * @param offerId offer identifier (for logging)
     * @return claims as map
     */
    private Map<String, Object> verifyDataIntegrityJWT(String jwtString, UUID offerId) {
        var offerIdentifier = offerId == null ? "" : offerId;
        try {
            if (jwtString == null || jwtString.isBlank()) {
                log.error("Data integrity JWT is missing for offer {}", offerIdentifier);
                throw new BadRequestException("Data integrity JWT is missing");
            }
            return JwtVerificationUtil.verifyJwt(jwtString, applicationProperties.getDataIntegrityKeySet());
        } catch (Exception e) {
            log.error("Failed setting up Data Integrity check of offer {} with JWKS {} - caused by {}", offerIdentifier, applicationProperties.getDataIntegrityJwks(), e.getMessage(), e);
            throw new BadRequestException(e.getMessage());
        }
    }

    /**
     * Parses offer data from JSON string to map.
     * Throws CredentialException on failure.
     * @param data JSON string
     * @param offerId offer identifier (for logging)
     * @return offer data map
     */
    private Map<String, Object> parseOfferData(String data, UUID offerId) {
        var offerIdentifier = offerId == null ? "" : offerId;
        try {
            if (data == null || data.isBlank()) {
                log.error("Offer data is missing or empty for offer {}", offerIdentifier);
                throw new CredentialException("Offer data is missing or empty");
            }
            return objectMapper.readValue(data, objectMapper.getTypeFactory().constructMapType(HashMap.class, String.class, Object.class));
        } catch (JsonProcessingException e) {
            log.error("Could not load offer data of offer {}", offerIdentifier, e);
            throw new CredentialException("Failed to parse offer data", e);
        }
    }

    /**
     * Unpacks and verifies credential offer data.
     * Performs data integrity check if required.
     * @param offerData offer data map
     * @param offerId offer identifier (for logging)
     * @return verified offer data map
     */
    public Map<String, Object> getVerifiedOfferData(Map<String, Object> offerData, UUID offerId) {
        var offerIdentifier = offerId == null ? "" : offerId;
        if (offerData == null || !offerData.containsKey("data")) {
            log.error("Issuer Management Error - Offer {} lacks any offer data", offerIdentifier);
            throw new BadRequestException("No offer data found");
        }
        Object dataObj = offerData.get("data");
        if (!(dataObj instanceof String data) || data.isBlank()) {
            log.error("Offer {} contains invalid or empty 'data' field", offerIdentifier);
            throw new BadRequestException("Offer data is invalid or empty");
        }
        if (isDataIntegrityRequired(offerData)) {
            return verifyDataIntegrityJWT(data, offerId);
        }
        return parseOfferData(data, offerId);
    }
}