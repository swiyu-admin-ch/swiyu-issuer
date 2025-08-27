package ch.admin.bj.swiyu.issuer.security;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import com.jayway.jsonpath.JsonPath;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
/**
 * Testing the coverage of securing endpoints using Keycloak
 */
class KeycloakJWTTest {

    static final String MANAGEMENT_BASE_URL = "/management/api/credentials";
    static final String STATUS_BASE_URL = "/management/api/status-list";
    static final String MINIMAL_PAYLOAD = """
            {"metadata_credential_supported_id":["test"],"credential_subject_data":{"hello":"world"}}
            """;

    static final DockerImageName KC_IMAGE = DockerImageName.parse("quay.io/keycloak/keycloak:25.0");
    static final Path REALM_FILE = Path.of("target/test/keycloak/realm-trust.json");
    static final int KC_PORT = 8080;
    static final String KC_CLIENT_ID = "issuer-client";
    static final String KC_CLIENT_SECRET = "Pa$$w0rd";

    static GenericContainer<?> keycloak;
    static String issuerUri;

    @Autowired
    MockMvc mvc;

    @BeforeAll
    static void startKeycloak() throws IOException {
        Files.createDirectories(REALM_FILE.getParent());
        Files.writeString(REALM_FILE, REALM_JSON);
        keycloak = new GenericContainer<>(KC_IMAGE)
                .withEnv("KEYCLOAK_ADMIN", "admin")
                .withEnv("KEYCLOAK_ADMIN_PASSWORD", "admin")
                .withCopyFileToContainer(MountableFile.forHostPath(REALM_FILE),
                        "/opt/keycloak/data/import/realm-trust.json")
                .withCommand("start-dev", String.format("--http-port=%d", KC_PORT),
                        "--hostname-strict=false", "--import-realm")
                .withExposedPorts(KC_PORT);
        keycloak.start();
        final int mapped = keycloak.getMappedPort(KC_PORT);
        issuerUri = String.format("http://localhost:%d/realms/trust", mapped);
    }

    @AfterAll
    static void stopKeycloak() throws IOException {
        if (keycloak != null)
            keycloak.stop();
        Files.deleteIfExists(REALM_FILE);
    }

    @DynamicPropertySource
    static void properties(final DynamicPropertyRegistry registry) {
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", () -> issuerUri);
        registry.add("spring.security.oauth2.resourceserver.jwt.jwk-set-uri",
                () -> issuerUri + "/protocol/openid-connect/certs");
        registry.add("spring.security.oauth2.resourceserver.jwt.jws-algorithms", () -> "RS256");
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
    void testManagementEndpoint_whenMissingAuthorizationHeader() throws Exception {
        mvc.perform(post(MANAGEMENT_BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(MINIMAL_PAYLOAD))
                .andExpect(status().isUnauthorized());

        mvc.perform(get(MANAGEMENT_BASE_URL + "/" + UUID.randomUUID()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testManagementEndpoint_whenWrongToken() throws Exception {
        final String fakeToken = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlLXVzZXIiLCJleHAiOjQ3MjM2NDgwMDB9.invalid-signature";
        final String fakeAuthorization = String.format("Bearer %s", fakeToken);

        mvc.perform(post(MANAGEMENT_BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(MINIMAL_PAYLOAD)
                        .header(HttpHeaders.AUTHORIZATION, fakeAuthorization))
                .andExpect(status().isUnauthorized());

        mvc.perform(get(MANAGEMENT_BASE_URL + "/" + UUID.randomUUID())
                        .header(HttpHeaders.AUTHORIZATION, fakeAuthorization))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testManagementEndpoint_whenAuthorized() throws Exception {
        final String token = getClientCredentialsToken(issuerUri, KC_CLIENT_ID, KC_CLIENT_SECRET);
        final String authorization = String.format("Bearer %s", token);

        mvc.perform(get(MANAGEMENT_BASE_URL + "/" + UUID.randomUUID())
                        .header(HttpHeaders.AUTHORIZATION, authorization))
                .andExpect(status().isNotFound());

        final var result = mvc.perform(post(MANAGEMENT_BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(MINIMAL_PAYLOAD)
                        .header(HttpHeaders.AUTHORIZATION, authorization))
                .andExpect(status().isOk())
                .andReturn();

        final String id = JsonPath.read(result.getResponse().getContentAsString(), "$.management_id");

        mvc.perform(get(MANAGEMENT_BASE_URL + "/" + id)
                        .header(HttpHeaders.AUTHORIZATION, authorization))
                .andExpect(status().isOk());
    }

    @Test
    void testStatusManagementEndpoint_whenUnauthorized() throws Exception {
        mvc.perform(post(STATUS_BASE_URL).contentType(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized());
        mvc.perform(get(STATUS_BASE_URL + "/" + UUID.randomUUID()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void testStatusManagementEndpoint_whenAuthorized() throws Exception {
        final String token = getClientCredentialsToken(issuerUri, KC_CLIENT_ID, KC_CLIENT_SECRET);
        final String authorization = String.format("Bearer %s", token);

        mvc.perform(post(STATUS_BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header(HttpHeaders.AUTHORIZATION, authorization))
                .andExpect(status().isBadRequest());

        mvc.perform(get(STATUS_BASE_URL + "/" + UUID.randomUUID())
                        .header(HttpHeaders.AUTHORIZATION, authorization))
                .andExpect(status().isNotFound());
    }

    private static String getClientCredentialsToken(final String issuer, final String clientId,
                                                    final String clientSecret) throws Exception {
        final String tokenEndpoint = String.format("%s/protocol/openid-connect/token", issuer);

        final OkHttpClient client = new OkHttpClient();
        final RequestBody form = new FormBody.Builder()
                .add("grant_type", "client_credentials")
                .add("client_id", clientId)
                .add("client_secret", clientSecret)
                .build();

        final Request req = new Request.Builder()
                .url(tokenEndpoint)
                .post(form)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .build();

        try (final var resp = client.newCall(req).execute()) {
            if (!resp.isSuccessful()) {
                throw new IllegalStateException("Keycloak token endpoint failed: " + resp.code() + " "
                        + resp.message());
            }
            Assertions.assertNotNull(resp.body());
            final String body = resp.body().string();
            return JsonPath.read(body, "$.access_token");
        }
    }

    private static final String REALM_JSON = """
            {
                "realm": "trust",
                "enabled": true,
                "sslRequired": "NONE",
                "clients": [
                    {
                        "clientId": "%s",
                        "enabled": true,
                        "protocol": "openid-connect",
                        "publicClient": false,
                        "secret": "%s",
                        "serviceAccountsEnabled": true,
                        "standardFlowEnabled": false,
                        "directAccessGrantsEnabled": false,
                        "redirectUris": [
                            "*"
                        ]
                    }
                ]
            }
            """.formatted(KC_CLIENT_ID, KC_CLIENT_SECRET);
}
