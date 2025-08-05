/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.oid4vci.service;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusType;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadataTechnical;
import ch.admin.bj.swiyu.issuer.service.CredentialFormatFactory;
import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ContextConfiguration;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static ch.admin.bj.swiyu.issuer.oid4vci.test.CredentialOfferTestData.createTestOffer;
import static ch.admin.bj.swiyu.issuer.oid4vci.test.JwtTestUtils.getJWTPayload;
import static java.util.Objects.nonNull;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@Testcontainers
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
class SdJwtCredentialIT {

    private final UUID preAuthCode = UUID.randomUUID();

    @Autowired
    private CredentialFormatFactory vcFormatFactory;
    @Autowired
    private ApplicationProperties applicationProperties;

    @Autowired
    private IssuerMetadataTechnical issuerMetadataTechnical;

    @Test
    void getMinimalSdJwtCredentialTestClaims_thenSuccess() {

        CredentialOffer credentialOffer = createTestOffer(preAuthCode, CredentialStatusType.OFFERED, "university_example_sd_jwt");

        CredentialRequestClass credentialRequest = CredentialRequestClass.builder().build();
        credentialRequest.setCredentialResponseEncryption(null);

        var vc = vcFormatFactory
                .getFormatBuilder(credentialOffer.getMetadataCredentialSupportedId().getFirst())
                .credentialOffer(credentialOffer)
                .credentialResponseEncryption(credentialRequest.getCredentialResponseEncryption())
                .credentialType(credentialOffer.getMetadataCredentialSupportedId())
                .buildCredentialEnvelope();

        Base64.Decoder decoder = Base64.getUrlDecoder();

        String credential = JsonPath.read(vc.getOid4vciCredentialJson(), "$.credential");
        String[] chunks = credential.split("\\.");
        String header = new String(decoder.decode(chunks[0]));
        String payload = new String(decoder.decode(chunks[1]));
        assertEquals("vc+sd-jwt", JsonPath.read(vc.getOid4vciCredentialJson(), "$.format"));

        // jwt headers
        assertEquals("vc+sd-jwt", JsonPath.read(header, "$.typ"));
        assertEquals("1.0", JsonPath.read(header, "$.ver"));

        // jwt payload - required fields iss-vct-iat
        assertEquals(applicationProperties.getIssuerId(), JsonPath.read(payload, "$.iss"));
        var offerMetadataCredentialSupportId = credentialOffer.getMetadataCredentialSupportedId().getFirst();
        assertEquals(issuerMetadataTechnical.getCredentialConfigurationById(offerMetadataCredentialSupportId).getVct(), JsonPath.read(payload, "$.vct"));
        assertTrue(nonNull(JsonPath.read(payload, "$.iat")));

        assertFalse(vc.getContentType().isBlank());
    }

    @Test
    void getSdJwtCredentialTestClaims_thenSuccess() {

        Instant now = Instant.now();
        Instant expiration = now.plus(30, ChronoUnit.DAYS);

        var credentialOffer = createTestOffer(preAuthCode, CredentialStatusType.OFFERED, "university_example_sd_jwt", now, expiration);

        CredentialRequestClass credentialRequest = CredentialRequestClass.builder().build();
        credentialRequest.setCredentialResponseEncryption(null);

        var vc = vcFormatFactory
                .getFormatBuilder(credentialOffer.getMetadataCredentialSupportedId().getFirst())
                .credentialOffer(credentialOffer)
                .credentialResponseEncryption(credentialRequest.getCredentialResponseEncryption())
                .credentialType(credentialOffer.getMetadataCredentialSupportedId())
                .buildCredentialEnvelope();

        Base64.Decoder decoder = Base64.getUrlDecoder();
        String credential = JsonPath.read(vc.getOid4vciCredentialJson(), "$.credential");
        String[] chunks = credential.split("\\.");
        String payload = new String(decoder.decode(chunks[1]));

        // jwt payload - optional fields
        // TODO add status test
        // TODO add key id
        List<String> sd = JsonPath.read(payload, "$._sd");
        assertEquals(3, sd.size());

        String alg = JsonPath.read(payload, "$._sd_alg");
        assertEquals("sha-256", alg);

        assertEquals(now.getEpochSecond(), ((Integer) JsonPath.read(payload, "$.nbf")).longValue());
        assertEquals(expiration.getEpochSecond(), ((Integer) JsonPath.read(payload, "$.exp")).longValue());
    }

    @Test
    void getSdJwtCredentialTestSD_thenSuccess() {

        var credentialOffer = createTestOffer(preAuthCode, CredentialStatusType.OFFERED, "university_example_sd_jwt");

        CredentialRequestClass credentialRequest = CredentialRequestClass.builder().build();
        credentialRequest.setCredentialResponseEncryption(null);

        var vc = vcFormatFactory
                .getFormatBuilder(credentialOffer.getMetadataCredentialSupportedId().getFirst())
                .credentialOffer(credentialOffer)
                .credentialResponseEncryption(credentialRequest.getCredentialResponseEncryption())
                .credentialType(credentialOffer.getMetadataCredentialSupportedId())
                .buildCredentialEnvelope();

        String credential = JsonPath.read(vc.getOid4vciCredentialJson(), "$.credential");
        String payload = getJWTPayload(credential);

        // Jwt payload - optional fields
        List<String> sd = JsonPath.read(payload, "$._sd");
        assertEquals(3
                , sd.size());
    }
}