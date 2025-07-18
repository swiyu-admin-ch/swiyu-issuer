package ch.admin.bj.swiyu.issuer.security;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.transaction.Transactional;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest()
@AutoConfigureMockMvc
@Testcontainers
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
@Transactional
/**
 * Testing the coverage of securing endpoints
 */
class OAuthSingleKeyJWTTest {
    static final String MANAGEMENT_BASE_URL = "/management/api/credentials";
    static final String STATUS_BASE_URL = "/management/api/status-list";
    static RSAKey rsaKey;
    static Path publicKeyPath = Path.of("target/test/public-key.pem");
    @Autowired
    private MockMvc mvc;

    @BeforeAll
    static void setupKey() throws JOSEException, IOException {
        // NOTE: Spring Security supports with fixed pem file only RSA as of 20250707
        rsaKey = new RSAKeyGenerator(2048).generate();
        // Write as pem to be loaded by Spring security
        String base64Encoded = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(rsaKey.toRSAPublicKey().getEncoded());
        String pem = "-----BEGIN PUBLIC KEY-----\n" + base64Encoded + "\n-----END PUBLIC KEY-----";
        Files.createDirectories(publicKeyPath.getParent());
        Files.createFile(publicKeyPath);
        Files.write(publicKeyPath, List.of(pem));
    }

    @AfterAll
    static void tearDownKey() throws IOException {
        Files.delete(publicKeyPath);
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("spring.security.oauth2.resourceserver.jwt.public-key-location", () -> "file:" + publicKeyPath.toAbsolutePath());
    }

    private static String createBearerToken() throws JOSEException {
        var now = new Date();
        var jwtClaims = new JWTClaimsSet.Builder()
                .issueTime(now)
                .expirationTime(new Date(now.getTime() + 1000))
                .build();
        var jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build();
        var nimbusJwt = new SignedJWT(jwsHeader, jwtClaims);
        var signer = new RSASSASigner(rsaKey);
        nimbusJwt.sign(signer);
        return nimbusJwt.serialize();
    }

    @Test
    void testPublicAccessWellKnown() throws Exception {
        mvc.perform(get("/oid4vci/.well-known/openid-configuration"))
                .andExpect(status().isOk());
        mvc.perform(get("/oid4vci/.well-known/oauth-authorization-server"))
                .andExpect(status().isOk());
        mvc.perform(get("/oid4vci/.well-known/openid-credential-issuer"))
                .andExpect(status().isOk());
    }

    @Test
    void testManagementEndpoint_whenUnauthorized() throws Exception {

        String minPayloadWithEmptySubject = String.format(
                "{\"metadata_credential_supported_id\": [\"%s\"], \"credential_subject_data\": {\"hello\": \"world\"}}",
                "test");
        // Expect the endpoints to block requests if not authorized
        mvc.perform(post(MANAGEMENT_BASE_URL).contentType(MediaType.APPLICATION_JSON).content(minPayloadWithEmptySubject))
                .andExpect(status().isUnauthorized());

        var randomUUID = UUID.randomUUID();
        mvc.perform(get(MANAGEMENT_BASE_URL + "/" + randomUUID))
                .andExpect(status().isUnauthorized());


    }

    @Test
    void testManagementEndpoint_whenAuthorized() throws Exception {
        var bearerToken = createBearerToken();
        var randomUUID = UUID.randomUUID();
        mvc.perform(get(MANAGEMENT_BASE_URL + "/" + randomUUID)
                        .header("Authorization", "Bearer " + bearerToken))
                .andExpect(status().isNotFound());
        String minPayloadWithEmptySubject = String.format(
                "{\"metadata_credential_supported_id\": [\"%s\"], \"credential_subject_data\": {\"hello\": \"world\"}}",
                "test");
        var result = mvc.perform(post(MANAGEMENT_BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(minPayloadWithEmptySubject)
                        .header("Authorization", "Bearer " + bearerToken))
                .andExpect(status().isOk())
                .andReturn();
        String id = JsonPath.read(result.getResponse().getContentAsString(), "$.management_id");
        mvc.perform(get(MANAGEMENT_BASE_URL + "/" + id)
                        .header("Authorization", "Bearer " + bearerToken))
                .andExpect(status().isOk());

    }

    @Test
    void testStatusManagementEndpoint_whenUnauthorized() throws Exception {
        var randomUUID = UUID.randomUUID();
        mvc.perform(post(STATUS_BASE_URL).contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized());
        mvc.perform(get(STATUS_BASE_URL + "/" + randomUUID))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testStatusManagementEndpoint_whenAuthorized() throws Exception {
        var bearerToken = createBearerToken();
        var randomUUID = UUID.randomUUID();
        mvc.perform(post(STATUS_BASE_URL).contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", "Bearer " + bearerToken))
                .andExpect(status().isBadRequest());
        mvc.perform(get(STATUS_BASE_URL + "/" + randomUUID)
                        .header("Authorization", "Bearer " + bearerToken))
                .andExpect(status().isNotFound());

    }
}