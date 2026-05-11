package ch.admin.bj.swiyu.issuer.oid4vci.intrastructure.web.controller;

import ch.admin.bj.swiyu.issuer.PostgreSQLContainerInitializer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialManagementRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusListRepository;
import ch.admin.bj.swiyu.issuer.management.infrastructure.web.controller.CredentialOfferTestHelper;
import ch.admin.bj.swiyu.issuer.service.trustregistry.TrustStatementCacheService;
import ch.admin.bj.swiyu.issuer.service.trustregistry.TrustStatementValidator;
import ch.admin.bj.swiyu.tsbuilder.IdTsBuilder;
import ch.admin.bj.swiyu.tsbuilder.PiaTsBuilder;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Happy-path integration tests verifying that Trust Statement JWTs (idTS / piaTS) are
 * successfully injected into the OID4VCI issuer metadata responses (EIDOMNI-881 / EIDOMNI-882).
 *
 * <p>Covers two endpoints:</p>
 * <ol>
 *   <li>Global: {@code GET /.well-known/openid-credential-issuer}</li>
 *   <li>Tenant-scoped: {@code GET /{tenantId}/.well-known/openid-credential-issuer}</li>
 * </ol>
 *
 * <p>Both the Trust Registry cache and the DID-based signature verification are mocked so that
 * no network calls are required. Trust Statements are built with the
 * {@code swiyu-ts-builder} library.</p>
 */
@SpringBootTest(properties = {
        "swiyu.trust-registry.api-url=https://trust-registry.example.ch",
        "swiyu.trust-registry.customer-key=test-key",
        "swiyu.trust-registry.customer-secret=test-secret"
})
@AutoConfigureMockMvc
@Testcontainers
@ActiveProfiles("test")
@ContextConfiguration(initializers = PostgreSQLContainerInitializer.class)
@Transactional
class WellKnownTrustStatementIT {

    /**
     * A well-formed {@code kid} matching the Trust Registry DID pattern required by
     * the {@code swiyu-ts-builder} validation (did:tdw / did:webvh with SCID + key fragment).
     */
    private static final String TRUST_REGISTRY_KID =
            "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch:api:v1:did#assert-key-01";

    /**
     * The issuer DID as configured in the test {@code application.yml}
     * ({@code application.issuer-id=did:tdw:example}).
     */
    private static final String ISSUER_DID = "did:tdw:example";

    /**
     * A syntactically valid subject DID used as the {@code sub} claim of the Trust Statements.
     */
    private static final String ISSUER_SUBJECT_DID =
            "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRBB1:identifier.admin.ch:api:v1:did";

    /**
     * The credential configuration key of a Protected VC entry in
     * {@code example_issuer_metadata.json}. This entry has {@code key_attestations_required}
     * set, so a piaTS must be injected into it (EIDOMNI-882).
     */
    private static final String PROTECTED_CREDENTIAL_KEY =
            "university_example_high_key_attestation_required_sd_jwt";

    /**
     * VCT of the Protected VC entry in {@code example_issuer_metadata.json}, resolved with
     * the test {@code external-url} ({@code http://localhost:8080}).
     * Must match the {@code vct} claim in the piaTS JWT so that VCT-based matching succeeds.
     */
    private static final String VALID_VCT = "http://localhost:8080/oid4vci/vct/my-vct-v01";

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private CredentialOfferRepository credentialOfferRepository;
    @Autowired
    private CredentialOfferStatusRepository credentialOfferStatusRepository;
    @Autowired
    private StatusListRepository statusListRepository;
    @Autowired
    private CredentialManagementRepository credentialManagementRepository;

    private CredentialOfferTestHelper testHelper;

    /**
     * Replaces the real Caffeine-backed cache so that trust statements are returned
     * directly without any Trust Registry network call.
     */
    @MockitoBean
    private TrustStatementCacheService trustStatementCacheService;

    /**
     * Replaces the DID-JWT validator so that signature verification always succeeds
     * without resolving a DID Document from the network.
     */
    @MockitoBean
    private TrustStatementValidator trustStatementValidator;

    @BeforeEach
    void setUp() {
        var statusRegistryUrl = "https://status-service-mock.bit.admin.ch/api/v1/statuslist/%s.jwt"
                .formatted(UUID.randomUUID());
        testHelper = new CredentialOfferTestHelper(
                mockMvc,
                credentialOfferRepository,
                credentialOfferStatusRepository,
                statusListRepository,
                credentialManagementRepository,
                statusRegistryUrl);
    }

    /**
     * Builds and signs a pair of Trust Statement JWTs (idTS + piaTS) using a fresh
     * ephemeral EC key, then stubs the cache service to return them and stubs
     * the validator to be a no-op for any JWT string.
     *
     * <p>Stubbing is done here so that mock and JWT construction happen atomically
     * without any timestamp skew between building the JWT and registering the mock.</p>
     *
     * @throws Exception if key generation or JWT building fails
     */
    private void stubTrustStatements() throws Exception {
        ECKey ecKey = new ECKeyGenerator(Curve.P_256).keyID("test-key").generate();
        ECDSASigner signer = new ECDSASigner(ecKey);

        Instant now = Instant.now();
        Instant expiry = now.plus(1, ChronoUnit.DAYS);

        SignedJWT idTs = new IdTsBuilder()
                .withKid(TRUST_REGISTRY_KID)
                .withSubject(ISSUER_SUBJECT_DID)
                .withValidity(now, expiry)
                .withStatus(1, "https://status.example.ch/list/1")
                .addEntityName("Test Issuer AG")
                .withIsStateActor(false)
                .addRegistryId("UID", "CHE-000.000.000")
                .build();
        idTs.sign(signer);

        SignedJWT piaTs = new PiaTsBuilder()
                .withKid(TRUST_REGISTRY_KID)
                .withSubject(ISSUER_SUBJECT_DID)
                .withValidity(now, expiry)
                .withStatus(1, "https://status.example.ch/list/1")
                .withCanIssue(VALID_VCT, null, "Beta credential", "Eligible per AwG Art.6b")
                .build();
        piaTs.sign(signer);

        String idTsJwt = idTs.serialize();
        String piaTsJwt = piaTs.serialize();

        when(trustStatementCacheService.getIdentityTrustStatement(ISSUER_DID)).thenReturn(idTsJwt);
        when(trustStatementCacheService.getAllProtectedIssuanceAuthorizationTrustStatements(ISSUER_DID))
                .thenReturn(List.of(piaTsJwt));
        // Stub for any JWT string so that re-serialised or slightly-different instances still pass
        doNothing().when(trustStatementValidator).validateSignature(anyString());
    }

/**
     * Verifies the happy path for the global (non-tenant) issuer metadata endpoint:
     * both idTS and piaTS are injected into {@code GET /.well-known/openid-credential-issuer}.
     *
     * @throws Exception if MockMvc or JWT operations fail
     */
    @Test
    void testGlobalEndpoint_TrustStatementsAreInjected() throws Exception {
        stubTrustStatements();

        mockMvc.perform(get("/.well-known/openid-credential-issuer"))
                .andExpect(status().isOk())
                // EIDOMNI-881: idTS field is present and populated at root level
                .andExpect(jsonPath("$.credential_issuer_identity_trust_statement").value(not(emptyOrNullString())))
                // EIDOMNI-882: piaTS field is present and populated in Protected VC configuration
                .andExpect(jsonPath(
                        "$.credential_configurations_supported."
                                + PROTECTED_CREDENTIAL_KEY
                                + ".protected_issuance_authorization_trust_statement")
                        .value(not(emptyOrNullString())));
    }

    /**
     * Verifies the happy path for the tenant-scoped issuer metadata endpoint:
     * both idTS and piaTS are injected into
     * {@code GET /{tenantId}/.well-known/openid-credential-issuer}.
     *
     * <p>A real credential offer is created in the database so that
     * {@code MetadataService.getUnsignedIssuerMetadataWithTS(tenantId)} can resolve the
     * {@code ConfigurationOverride} and derive the effective issuer DID.</p>
     *
     * @throws Exception if MockMvc or JWT operations fail
     */
    @Test
    void testTenantEndpoint_TrustStatementsAreInjected() throws Exception {
        String tenantPath = testHelper.createBasicOfferJsonAndGetTenantID();
        stubTrustStatements();

        mockMvc.perform(get(tenantPath + "/.well-known/openid-credential-issuer")
                        .accept("application/json"))
                .andExpect(status().isOk())
                // EIDOMNI-881: idTS field is present and populated at root level
                .andExpect(jsonPath("$.credential_issuer_identity_trust_statement").value(not(emptyOrNullString())))
                // EIDOMNI-882: piaTS field is present and populated in Protected VC configuration
                .andExpect(jsonPath(
                        "$.credential_configurations_supported."
                                + PROTECTED_CREDENTIAL_KEY
                                + ".protected_issuance_authorization_trust_statement")
                        .value(not(emptyOrNullString())));
    }
}
