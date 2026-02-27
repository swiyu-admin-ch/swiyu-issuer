package ch.admin.bj.swiyu.issuer.oid4vci.service;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.common.profile.SwissProfileVersions;
import ch.admin.bj.swiyu.issuer.dto.oid4vci.CredentialEnvelopeDto;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.ConfigurationOverride;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferMetadata;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusType;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.CredentialRequestClass;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.service.offer.CredentialFormatFactory;
import ch.admin.bj.swiyu.issuer.service.enc.JweService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

import static ch.admin.bj.swiyu.issuer.common.date.TimeUtils.instantToRoundedUnixTimestamp;
import static ch.admin.bj.swiyu.issuer.oid4vci.test.CredentialOfferTestData.createTestOffer;
import static ch.admin.bj.swiyu.issuer.oid4vci.test.JwtTestUtils.getJWTPayload;
import static java.util.Objects.nonNull;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
class SdJwtCredentialIT {

    final private static ObjectMapper mapper = new ObjectMapper();
    private final UUID preAuthCode = UUID.randomUUID();
    @Autowired
    private CredentialFormatFactory vcFormatFactory;
    @Autowired
    private ApplicationProperties applicationProperties;
    @Autowired
    private JweService jweService;
    @Autowired
    private IssuerMetadata issuerMetadata;

    @Test
    void getMinimalSdJwtCredentialTestClaims_thenSuccess() {

        CredentialOffer credentialOffer = createTestOffer(preAuthCode, CredentialOfferStatusType.OFFERED, "university_example_sd_jwt");

        CredentialRequestClass credentialRequest = CredentialRequestClass.builder().build();
        credentialRequest.setCredentialResponseEncryption(null);

        var vc = vcFormatFactory
                .getFormatBuilder(credentialOffer.getMetadataCredentialSupportedId().getFirst())
                .credentialOffer(credentialOffer)
                .credentialResponseEncryption(jweService.issuerMetadataWithEncryptionOptions().getResponseEncryption(), credentialRequest.getCredentialResponseEncryption())
                .credentialType(credentialOffer.getMetadataCredentialSupportedId())
                .buildCredentialEnvelope();

        Base64.Decoder decoder = Base64.getUrlDecoder();

        String credential = getReadFirstCredential(vc);
        String[] chunks = credential.split("\\.");
        String header = new String(decoder.decode(chunks[0]));
        String payload = new String(decoder.decode(chunks[1]));

        // jwt headers
        assertEquals("vc+sd-jwt", JsonPath.read(header, "$.typ"));
        assertEquals(SwissProfileVersions.VC_PROFILE_VERSION, JsonPath.read(header, "$.profile_version"));

        // jwt payload - required fields iss-vct-iat
        assertEquals(applicationProperties.getIssuerId(), JsonPath.read(payload, "$.iss"));
        var offerMetadataCredentialSupportId = credentialOffer.getMetadataCredentialSupportedId().getFirst();
        assertEquals(issuerMetadata.getCredentialConfigurationById(offerMetadataCredentialSupportId).getVct(), JsonPath.read(payload, "$.vct"));
        assertTrue(nonNull(JsonPath.read(payload, "$.iat")));

        assertFalse(vc.getContentType().isBlank());
    }

    @Test
    void getSdJwtCredentialTestClaims_thenSuccess() {

        Instant now = Instant.now();
        Instant expiration = now.plus(30, ChronoUnit.DAYS);

        var credentialOffer = createTestOffer(preAuthCode, CredentialOfferStatusType.OFFERED, "university_example_sd_jwt", now, expiration);

        CredentialRequestClass credentialRequest = CredentialRequestClass.builder().build();
        credentialRequest.setCredentialResponseEncryption(null);

        CredentialEnvelopeDto vc = vcFormatFactory
                .getFormatBuilder(credentialOffer.getMetadataCredentialSupportedId().getFirst())
                .credentialOffer(credentialOffer)
                .credentialResponseEncryption(jweService.issuerMetadataWithEncryptionOptions().getResponseEncryption(), credentialRequest.getCredentialResponseEncryption())
                .credentialType(credentialOffer.getMetadataCredentialSupportedId())
                .buildCredentialEnvelope();

        Base64.Decoder decoder = Base64.getUrlDecoder();
        String credential = getReadFirstCredential(vc);
        String[] chunks = credential.split("\\.");
        String payload = new String(decoder.decode(chunks[1]));

        // jwt payload - optional fields
        // TODO add status test
        // TODO add key id
        List<String> sd = JsonPath.read(payload, "$._sd");
        assertEquals(3, sd.size());

        String alg = JsonPath.read(payload, "$._sd_alg");
        assertEquals("sha-256", alg);

        // timestamps are rounded down to the day, hence the less than
        assertEquals(instantToRoundedUnixTimestamp(Instant.now()), ((Integer) JsonPath.read(payload, "$.nbf")).longValue());
        assertEquals(instantToRoundedUnixTimestamp(Instant.now()), ((Integer) JsonPath.read(payload, "$.iat")).longValue());
        assertEquals(instantToRoundedUnixTimestamp(expiration), ((Integer) JsonPath.read(payload, "$.exp")).longValue());
    }

    @Test
    void getSdJwtCredentialV2TestClaims_thenSuccess() {

        Instant now = Instant.now();
        Instant expiration = now.plus(30, ChronoUnit.DAYS);

        var credentialOffer = createTestOffer(preAuthCode, CredentialOfferStatusType.OFFERED, "university_example_sd_jwt", now, expiration);

        CredentialRequestClass credentialRequest = CredentialRequestClass.builder().build();
        credentialRequest.setCredentialResponseEncryption(null);

        CredentialEnvelopeDto vc = vcFormatFactory
                .getFormatBuilder(credentialOffer.getMetadataCredentialSupportedId().getFirst())
                .credentialOffer(credentialOffer)
                .credentialResponseEncryption(jweService.issuerMetadataWithEncryptionOptions().getResponseEncryption(), credentialRequest.getCredentialResponseEncryption())
                .credentialType(credentialOffer.getMetadataCredentialSupportedId())
                .buildCredentialEnvelope();

        Base64.Decoder decoder = Base64.getUrlDecoder();
        List<HashMap<String, String>> credentialsMap = JsonPath.read(vc.getOid4vciCredentialJson(), "$.credentials");
        var credentials = credentialsMap.stream().map(c -> c.values().stream().toList()).flatMap(List::stream).collect(Collectors.toList());

        Set<String> payloads = new HashSet<>();
        Set<String> sdHashes = new HashSet<>();
        for (var credential : credentials) {
            String[] chunks = credential.split("\\.");
            String payload = new String(decoder.decode(chunks[1]));
            payloads.add(payload);

            List<String> sd = JsonPath.read(payload, "$._sd");
            assertEquals(3, sd.size());
            sdHashes.addAll(sd);

            String alg = JsonPath.read(payload, "$._sd_alg");
            assertEquals("sha-256", alg);

            // timestamps are rounded down to the day to break traceability
            assertEquals(instantToRoundedUnixTimestamp(Instant.now()), ((Integer) JsonPath.read(payload, "$.nbf")).longValue());
            assertEquals(instantToRoundedUnixTimestamp(Instant.now()), ((Integer) JsonPath.read(payload, "$.iat")).longValue());
            assertEquals(instantToRoundedUnixTimestamp(expiration), ((Integer) JsonPath.read(payload, "$.exp")).longValue());
        }
        // test that payloads within the same batch are unique
        assertEquals(credentials.size(), payloads.size());
        // test that the sd hashes are all unique
        assertEquals(credentials.size() * 3, sdHashes.size());
    }

    @Test
    void getSdJwtCredentialTestSD_thenSuccess() {

        var credentialOffer = createTestOffer(preAuthCode, CredentialOfferStatusType.OFFERED, "university_example_sd_jwt");

        CredentialRequestClass credentialRequest = CredentialRequestClass.builder().build();
        credentialRequest.setCredentialResponseEncryption(null);

        var vc = vcFormatFactory
                .getFormatBuilder(credentialOffer.getMetadataCredentialSupportedId().getFirst())
                .credentialOffer(credentialOffer)
                .credentialResponseEncryption(jweService.issuerMetadataWithEncryptionOptions().getResponseEncryption(), credentialRequest.getCredentialResponseEncryption())
                .credentialType(credentialOffer.getMetadataCredentialSupportedId())
                .buildCredentialEnvelope();

        String credential = getReadFirstCredential(vc);
        String payload = getJWTPayload(credential);

        // Jwt payload - optional fields
        List<String> sd = JsonPath.read(payload, "$._sd");
        assertEquals(3
                , sd.size());
    }

    private static String getReadFirstCredential(CredentialEnvelopeDto vc) {
        String credential = JsonPath.read(vc.getOid4vciCredentialJson(), "$.credentials[0].credential");
        if (credential == null || credential.isBlank()) {
            throw new IllegalStateException("Expected first credential at path $.credentials[0].credential");
        }
        return credential;
    }

    @Test
    void getSdJwtCredential_withVctMetadataUri_thenSuccess() {

        var vctIntegrity = "vct#integrity";
        var vctMetadataUri = "vct_metadata_uri_example";
        var vctMetadataUriIntegrity = "vct_metadata_uri#integrity_example";

        var credentialOfferMetadata = new CredentialOfferMetadata(null, vctIntegrity, vctMetadataUri, vctMetadataUriIntegrity);
        var credentialOffer = createTestOffer(preAuthCode, CredentialOfferStatusType.OFFERED, "university_example_sd_jwt", credentialOfferMetadata);

        CredentialRequestClass credentialRequest = CredentialRequestClass.builder().build();
        credentialRequest.setCredentialResponseEncryption(null);

        var vc = vcFormatFactory
                .getFormatBuilder(credentialOffer.getMetadataCredentialSupportedId().getFirst())
                .credentialOffer(credentialOffer)
                .credentialResponseEncryption(jweService.issuerMetadataWithEncryptionOptions().getResponseEncryption(), credentialRequest.getCredentialResponseEncryption())
                .credentialType(credentialOffer.getMetadataCredentialSupportedId())
                .buildCredentialEnvelope();

        String credential = getReadFirstCredential(vc);
        JsonObject payload = JsonParser.parseString(getJWTPayload(credential)).getAsJsonObject();

        assertEquals(vctIntegrity, payload.get("vct#integrity").getAsString());
        assertEquals(vctMetadataUri, payload.get("vct_metadata_uri").getAsString());
        assertEquals(vctMetadataUriIntegrity, payload.get("vct_metadata_uri#integrity").getAsString());
    }

    @Test
    void getSdJwtCredential_withoutAnyMetadata_thenSuccess() {

        var credentialOfferMetadata = new CredentialOfferMetadata(null, null, null, null);
        var credentialOffer = createTestOffer(preAuthCode, CredentialOfferStatusType.OFFERED, "university_example_sd_jwt", credentialOfferMetadata);

        CredentialRequestClass credentialRequest = CredentialRequestClass.builder().build();
        credentialRequest.setCredentialResponseEncryption(null);

        var vc = vcFormatFactory
                .getFormatBuilder(credentialOffer.getMetadataCredentialSupportedId().getFirst())
                .credentialOffer(credentialOffer)
                .credentialResponseEncryption(jweService.issuerMetadataWithEncryptionOptions().getResponseEncryption(), credentialRequest.getCredentialResponseEncryption())
                .credentialType(credentialOffer.getMetadataCredentialSupportedId())
                .buildCredentialEnvelope();

        String credential = getReadFirstCredential(vc);
        JsonObject payload = JsonParser.parseString(getJWTPayload(credential)).getAsJsonObject();

        assertFalse(payload.has("vct#integrity"));
        assertFalse(payload.has("vct_metadata_uri"));
        assertFalse(payload.has("vct_metadata_uri#integrity"));
    }

    @Test
    void getSdJwtCredentialTestSD_whenOverriding_thenSuccess() throws ParseException {
        var overrideDid = "did:example:override";
        var overrideVerificationMethod = overrideDid + "#key1";

        var credentialOffer = createTestOffer(preAuthCode, CredentialOfferStatusType.OFFERED, "university_example_sd_jwt", new ConfigurationOverride(overrideDid, overrideVerificationMethod, null, null));

        CredentialRequestClass credentialRequest = CredentialRequestClass.builder().build();
        credentialRequest.setCredentialResponseEncryption(null);

        var vc = vcFormatFactory
                .getFormatBuilder(credentialOffer.getMetadataCredentialSupportedId().getFirst())
                .credentialOffer(credentialOffer)
                .credentialResponseEncryption(jweService.issuerMetadataWithEncryptionOptions().getResponseEncryption(), credentialRequest.getCredentialResponseEncryption())
                .credentialType(credentialOffer.getMetadataCredentialSupportedId())
                .buildCredentialEnvelope();

        String credential = getReadFirstCredential(vc);
        var issuedJwt = SignedJWT.parse(credential.split("~")[0]);
        assertEquals(overrideVerificationMethod, issuedJwt.getHeader().getKeyID());
        assertEquals(overrideDid, issuedJwt.getJWTClaimsSet().getIssuer());
    }

    @Test
    void getSdJwtCredentialV2TestTracing_thenSuccess() {

        assertThat(applicationProperties.isEnableVcHashStorage())
                .as("This Test requires VC Hash Storage to be active")
                .isTrue();
        Instant now = Instant.now();
        Instant expiration = now.plus(30, ChronoUnit.DAYS);

        var credentialOffer = createTestOffer(preAuthCode, CredentialOfferStatusType.OFFERED, "university_example_sd_jwt", now, expiration);

        CredentialRequestClass credentialRequest = CredentialRequestClass.builder().build();
        credentialRequest.setCredentialResponseEncryption(null);

        CredentialEnvelopeDto vc = vcFormatFactory
                .getFormatBuilder(credentialOffer.getMetadataCredentialSupportedId().getFirst())
                .credentialOffer(credentialOffer)
                .credentialResponseEncryption(jweService.issuerMetadataWithEncryptionOptions().getResponseEncryption(), credentialRequest.getCredentialResponseEncryption())
                .credentialType(credentialOffer.getMetadataCredentialSupportedId())
                .buildCredentialEnvelope();

        assertThat(credentialOffer.getVcHashes())
                .as("Should have created a finger print for each VC")
                .hasSize(jweService.issuerMetadataWithEncryptionOptions().getIssuanceBatchSize());
        for (var vcHash : credentialOffer.getVcHashes()) {
            assertThat(vc.getOid4vciCredentialJson())
                    .as("The VC hash should match to the ancillary data of one of the created VCs")
                    .contains(vcHash);
        }
    }
}

