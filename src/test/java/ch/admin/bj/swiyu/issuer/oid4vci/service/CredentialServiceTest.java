/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.service;

import ch.admin.bj.swiyu.issuer.oid4vci.api.CredentialRequestDto;
import ch.admin.bj.swiyu.issuer.oid4vci.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.oid4vci.common.config.OpenIdIssuerConfiguration;
import ch.admin.bj.swiyu.issuer.oid4vci.common.exception.OAuthException;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.credentialoffer.CredentialOfferRepository;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.credentialoffer.CredentialStatus;
import ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.metadata.IssuerMetadataTechnical;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialServiceTest {

    @Mock
    private CredentialOfferRepository credentialOfferRepository;
    @Mock
    private IssuerMetadataTechnical issuerMetadata;
    @Mock
    private CredentialFormatFactory vcFormatFactory;
    @Mock
    private ApplicationProperties applicationProperties;
    @Mock
    private OpenIdIssuerConfiguration openIdIssuerConfiguration;

    @Test
    void givenExpiredToken_whenGetCredential_thenThrowOAuthException() throws OAuthException {
        // Given
        var service = new CredentialService(credentialOfferRepository, issuerMetadata, vcFormatFactory, applicationProperties, null, openIdIssuerConfiguration);
        var uuid = UUID.randomUUID();
        var offerData = new HashMap<String, Object>() {{
            put("data", "data");
            put("otherStuff", "data");
        }};

        var offer = getCredentialOffer(CredentialStatus.IN_PROGRESS, offerData, uuid, uuid, UUID.randomUUID());
        offer.setTokenExpirationTimestamp(Instant.now().minusSeconds(600).getEpochSecond());

        when(credentialOfferRepository.findByAccessToken(uuid)).thenReturn(Optional.of(offer));

        // WHEN credential is created for offer with expired timestamp
        var credentialRequestDto = new CredentialRequestDto(
                "vc+sd-jwt",
                new HashMap<>(),
                null
        );
        var ex = assertThrows(OAuthException.class, () -> service.createCredential(credentialRequestDto, uuid.toString()));

        // THEN Status is changed and offer data is cleared
        assertEquals("INVALID_REQUEST", ex.getError().toString());
        assertEquals("AccessToken expired.", ex.getMessage());
    }

    @Test
    void givenExpiredOffer_whenCredentialIsCreated_throws() {
        // GIVEN
        var service = new CredentialService(credentialOfferRepository, issuerMetadata, vcFormatFactory, applicationProperties, null, openIdIssuerConfiguration);
        var uuid = UUID.randomUUID();
        var preAuthorizedCode = UUID.randomUUID();
        var offerData = new HashMap<String, Object>() {{
            put("data", "data");
            put("otherStuff", "data");
        }};

        var offer = getCredentialOffer(CredentialStatus.OFFERED, offerData, uuid, preAuthorizedCode, UUID.randomUUID());
        offer.setOfferExpirationTimestamp(Instant.now().minusSeconds(10).getEpochSecond());

        when(credentialOfferRepository.findByAccessToken(uuid)).thenReturn(Optional.of(offer));

        // WHEN credential is created for offer with expired timestamp
        var credentialRequestDto = new CredentialRequestDto(
                "vc+sd-jwt",
                new HashMap<>(),
                null
        );
        var ex = assertThrows(OAuthException.class, () -> service.createCredential(credentialRequestDto, uuid.toString()));

        // THEN Status is changed and offer data is cleared
        assertEquals(CredentialStatus.EXPIRED, offer.getCredentialStatus());
        assertNull(offer.getOfferData());
        assertEquals("INVALID_TOKEN", ex.getError().toString());
        assertEquals("Invalid accessToken", ex.getMessage());
    }

    @Test
    void givenExpiredOffer_whenTokenIsCreated_throws() {
        // GIVEN
        var service = new CredentialService(credentialOfferRepository, issuerMetadata, vcFormatFactory, applicationProperties, null, openIdIssuerConfiguration);
        var uuid = UUID.randomUUID();
        var offerData = new HashMap<String, Object>() {{
            put("data", "data");
            put("otherStuff", "data");
        }};
        var offer = getCredentialOffer(CredentialStatus.OFFERED, offerData, uuid, uuid, UUID.randomUUID());
        offer.setOfferExpirationTimestamp(Instant.now().minusSeconds(10).getEpochSecond());
        when(credentialOfferRepository.findByPreAuthorizedCode(uuid)).thenReturn(Optional.of(offer));

        // WHEN credential is created for offer with expired timestamp
        var ex = assertThrows(OAuthException.class, () -> service.issueOAuthToken(uuid.toString()));

        // THEN Status is changed and offer data is cleared
        assertEquals(CredentialStatus.EXPIRED, offer.getCredentialStatus());
        assertNull(offer.getOfferData());
        assertEquals("INVALID_GRANT", ex.getError().toString());
        assertEquals("Invalid preAuthCode", ex.getMessage());
    }

    private static CredentialOffer getCredentialOffer(CredentialStatus status, HashMap<String, Object> offerData, UUID accessToken, UUID preAuthorizedCode, UUID nonce) {

        return new CredentialOffer(
                UUID.randomUUID(),
                status,
                Collections.emptyList(),
                offerData,
                new HashMap<>(),
                accessToken,
                null,
                null,
                Instant.now().plusSeconds(600).getEpochSecond(),
                nonce,
                preAuthorizedCode,
                Instant.now().plusSeconds(600).getEpochSecond(),
                Instant.now(),
                Instant.now(),
                null,
                null
        );
    }
}