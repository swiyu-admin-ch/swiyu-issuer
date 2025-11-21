package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.DemonstratingProofOfPossessionException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusType;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.SelfContainedNonce;
import ch.admin.bj.swiyu.issuer.util.DemonstratingProofOfPossessionTestUtil;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import jakarta.transaction.Transactional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpRequest;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.net.URI;
import java.time.Instant;
import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest()
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
@Transactional
class DemonstratingProofOfPossessionIT {

    public static final String DPOP_NONCE_HEADER = "DPoP-Nonce";
    @Autowired
    private ApplicationProperties applicationProperties;
    @Autowired
    private DemonstratingProofOfPossessionService demonstratingProofOfPossessionService;
    @Autowired
    private CredentialOfferRepository credentialOfferRepository;
    private CredentialOffer testCredentialOffer;
    private ECKey dpopKey;

    public static Stream<String> faultyNonceSource() {
        return Stream.of(
                // Only UUID; No timestamp
                UUID.randomUUID().toString(), // EIDSEC-633
                // Attempt ot inject some other data
                new SelfContainedNonce().getNonce() + "::" + "SomeOtherData",
                // Deprecated Nonce
                UUID.randomUUID() + "::" + Instant.now().minusSeconds(120).toString(),
                // Nonce from the future
                UUID.randomUUID() + "::" + Instant.now().plusSeconds(120).toString()
        );
    }

    @BeforeEach
    void setUp() {
        testCredentialOffer = CredentialOffer.builder()
                .id(UUID.randomUUID())
                .preAuthorizedCode(UUID.randomUUID())
                .accessToken(UUID.randomUUID())
                .credentialStatus(CredentialStatusType.OFFERED)
                .nonce(UUID.randomUUID())
                .build();
        credentialOfferRepository.save(testCredentialOffer);
        dpopKey = assertDoesNotThrow(() -> new ECKeyGenerator(Curve.P_256).keyID("test-key-1").keyUse(KeyUse.SIGNATURE).generate());
    }

    @Test
    void whenCorrectProofOfPossession_thenSuccess() {
        HttpRequest baseTestHttpRequest = createMockRequest();
        String nonce = getDPoPNonce();
        registerDPoP(baseTestHttpRequest, nonce);
        nonce = getDPoPNonce();
        var credentialRequest = mockCredentialHttpRequest(baseTestHttpRequest);
        var requestCredentialDPoP = getDPoPJWT(credentialRequest, nonce, testCredentialOffer.getAccessToken().toString());
        assertDoesNotThrow(() -> demonstratingProofOfPossessionService.validateDpop(testCredentialOffer.getAccessToken().toString(), requestCredentialDPoP, credentialRequest));
    }

    @Test
    void whenMissingAccessToken_thenBadRequest() {
        HttpRequest baseTestHttpRequest = createMockRequest();
        String nonce = getDPoPNonce();
        registerDPoP(baseTestHttpRequest, nonce);
        nonce = getDPoPNonce();
        var requestCredentialDPoP = getDPoPJWT(mockCredentialHttpRequest(baseTestHttpRequest), nonce, null);
        String accessToken = testCredentialOffer.getAccessToken().toString();
        assertThrows(DemonstratingProofOfPossessionException.class, () -> demonstratingProofOfPossessionService.validateDpop(accessToken, requestCredentialDPoP, baseTestHttpRequest));
    }

    @Test
    void whenMismatchingAccessToken_thenBadRequest() {
        HttpRequest baseTestHttpRequest = createMockRequest();
        String nonce = getDPoPNonce();
        registerDPoP(baseTestHttpRequest, nonce);
        nonce = getDPoPNonce();
        var requestCredentialDPoP = getDPoPJWT(mockCredentialHttpRequest(baseTestHttpRequest), nonce, UUID.randomUUID().toString());
        String accessToken = testCredentialOffer.getAccessToken().toString();
        assertThrows(DemonstratingProofOfPossessionException.class, () -> demonstratingProofOfPossessionService.validateDpop(accessToken, requestCredentialDPoP, baseTestHttpRequest));
    }

    @Test
    void whenReusedNonce_thenBadRequest() {
        HttpRequest baseTestHttpRequest = createMockRequest();
        String nonce = getDPoPNonce();
        registerDPoP(baseTestHttpRequest, nonce);
        var credentialRequest = mockCredentialHttpRequest(baseTestHttpRequest);
        var requestCredentialDPoP = getDPoPJWT(credentialRequest, nonce, testCredentialOffer.getAccessToken().toString());
        String accessToken = testCredentialOffer.getAccessToken().toString();
        assertThrows(DemonstratingProofOfPossessionException.class, () -> demonstratingProofOfPossessionService.validateDpop(accessToken, requestCredentialDPoP, credentialRequest));
    }

    @ParameterizedTest
    @MethodSource("faultyNonceSource")
    void whenFaultyNonce_thenBadRequest(String faultyNonce) {
        HttpRequest baseTestHttpRequest = createMockRequest();
        var tokenRequest = mockTokenHttpRequest(baseTestHttpRequest);
        var registrationDPoP = getDPoPJWT(tokenRequest, faultyNonce, null);
        String preAuthCode = testCredentialOffer.getPreAuthorizedCode().toString();
        assertThrows(DemonstratingProofOfPossessionException.class, () -> demonstratingProofOfPossessionService.registerDpop(preAuthCode, registrationDPoP, tokenRequest));
    }

    private HttpRequest createMockRequest() {
        return new MockClientHttpRequest(HttpMethod.POST, applicationProperties.getExternalUrl());
    }

    private void registerDPoP(HttpRequest baseTestHttpRequest, String nonce) {
        var tokenRequest = mockTokenHttpRequest(baseTestHttpRequest);
        var registrationDPoP = getDPoPJWT(tokenRequest, nonce, null);
        assertDoesNotThrow(() -> demonstratingProofOfPossessionService.registerDpop(testCredentialOffer.getPreAuthorizedCode().toString(), registrationDPoP, tokenRequest));
    }

    private HttpRequest mockTokenHttpRequest(HttpRequest baseTestHttpRequest) {
        return assertDoesNotThrow(() -> new MockClientHttpRequest(baseTestHttpRequest.getMethod(), new URI(baseTestHttpRequest.getURI() + "/token")));
    }

    private HttpRequest mockCredentialHttpRequest(HttpRequest baseTestHttpRequest) {
        return assertDoesNotThrow(() -> new MockClientHttpRequest(baseTestHttpRequest.getMethod(), new URI(baseTestHttpRequest.getURI() + "/credential")));
    }

    private String getDPoPJWT(HttpRequest httpRequest, String nonce, String accessToken) {
        return DemonstratingProofOfPossessionTestUtil.createDPoPJWT(httpRequest.getMethod().toString(), httpRequest.getURI().toString(), accessToken, dpopKey, nonce);
    }

    private String getDPoPNonce() {
        var dpopHeaders = new HttpHeaders();
        demonstratingProofOfPossessionService.addDpopNonce(dpopHeaders);
        return assertDoesNotThrow(() -> dpopHeaders.get(DPOP_NONCE_HEADER).getFirst());
    }


}
