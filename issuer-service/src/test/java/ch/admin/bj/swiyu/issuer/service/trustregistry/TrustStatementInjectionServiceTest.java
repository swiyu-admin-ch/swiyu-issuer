package ch.admin.bj.swiyu.issuer.service.trustregistry;

import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.AttackPotentialResistance;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialConfiguration;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.KeyAttestationRequirement;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.SupportedProofType;
import ch.admin.bj.swiyu.jwtvalidator.JwtValidatorException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link TrustStatementInjectionService}.
 *
 * <p>Verifies that idTS and piaTS trust statements are correctly injected into
 * {@link IssuerMetadata}, that piaTS JWTs are matched per {@code vct} claim (1:N mapping),
 * and that cache invalidation is triggered on signature verification failure.</p>
 */
class TrustStatementInjectionServiceTest {

    /**
     * Shared EC key for signing test JWTs – generated once to avoid per-test crypto overhead.
     */
    private static final ECKey TEST_KEY;
    private static final String ISSUER_DID = "did:tdw:test:issuer";
    private static final String VCT_ELFA = "https://example.ch/vct/elfa";
    private static final String VCT_MDL = "https://example.ch/vct/mdl";
    private static final String ID_TS = "id.ts.jwt";

    static {
        try {
            TEST_KEY = new ECKeyGenerator(Curve.P_256).generate();
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private TrustStatementCacheService cacheService;
    private TrustStatementValidator validator;
    private TrustStatementInjectionService trustStatementInjectionService;

    /**
     * Builds a signed piaTS JWT with the given VCT inside the {@code can_issue} claim.
     */
    private static String buildPiaTsJwt(String vct) throws Exception {
        var header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new JOSEObjectType("jwt"))
                .build();
        var claims = new JWTClaimsSet.Builder()
                .issuer("did:tdw:trust-registry:issuer")
                .claim("can_issue", Map.of("vct", vct, "vct_name", "Test VC"))
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(3600)))
                .build();
        var jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner(TEST_KEY));
        return jwt.serialize();
    }

    @BeforeEach
    void setUp() {
        cacheService = mock(TrustStatementCacheService.class);
        validator = mock(TrustStatementValidator.class);
        trustStatementInjectionService = new TrustStatementInjectionService(cacheService, validator);
    }

    private IssuerMetadata createMetadata(boolean withProtectedVc, String vct) {
        IssuerMetadata metadata = new IssuerMetadata();
        Map<String, CredentialConfiguration> configs = new HashMap<>();

        CredentialConfiguration config = new CredentialConfiguration();
        config.setVct(vct);
        Map<String, SupportedProofType> proofTypes = new HashMap<>();
        SupportedProofType proofType = new SupportedProofType();

        if (withProtectedVc) {
            var keyAttReq = KeyAttestationRequirement.builder()
                    .keyStorage(List.of(AttackPotentialResistance.ISO_18045_ENHANCED_BASIC))
                    .build();
            proofType.setKeyAttestationRequirement(keyAttReq);
        }

        proofTypes.put("jwt", proofType);
        config.setProofTypesSupported(proofTypes);
        configs.put("TestFormat", config);

        metadata.setCredentialConfigurationSupported(configs);
        return metadata;
    }

    @Test
    void injectTrustStatements_injectsIdTs_whenAvailableInCache() {
        when(cacheService.getIdentityTrustStatement(ISSUER_DID)).thenReturn(ID_TS);

        IssuerMetadata metadata = createMetadata(false, null);
        trustStatementInjectionService.injectTrustStatements(metadata, ISSUER_DID);

        assertThat(metadata.getCredentialIssuerIdentityTrustStatement()).isEqualTo(ID_TS);
    }

    @Test
    void injectTrustStatements_doesNotInjectIdTs_whenNotInCache() {
        when(cacheService.getIdentityTrustStatement(ISSUER_DID)).thenReturn(null);

        IssuerMetadata metadata = createMetadata(false, null);
        trustStatementInjectionService.injectTrustStatements(metadata, ISSUER_DID);

        assertThat(metadata.getCredentialIssuerIdentityTrustStatement()).isNull();
    }

    @Test
    void injectTrustStatements_injectsPiaTs_forMatchingVct() throws Exception {
        String elfaPiaTs = buildPiaTsJwt(VCT_ELFA);
        String mdlPiaTs = buildPiaTsJwt(VCT_MDL);
        when(cacheService.getAllProtectedIssuanceAuthorizationTrustStatements(ISSUER_DID))
                .thenReturn(List.of(elfaPiaTs, mdlPiaTs));

        IssuerMetadata metadata = createMetadata(true, VCT_ELFA);
        trustStatementInjectionService.injectTrustStatements(metadata, ISSUER_DID);

        CredentialConfiguration config = metadata.getCredentialConfigurationSupported().get("TestFormat");
        assertThat(config.getProtectedIssuanceAuthorizationTrustStatement()).isEqualTo(elfaPiaTs);
    }

    @Test
    void injectTrustStatements_doesNotInjectPiaTs_whenNoVctMatch() throws Exception {
        String mdlPiaTs = buildPiaTsJwt(VCT_MDL);
        when(cacheService.getAllProtectedIssuanceAuthorizationTrustStatements(ISSUER_DID))
                .thenReturn(List.of(mdlPiaTs));

        IssuerMetadata metadata = createMetadata(true, VCT_ELFA);
        trustStatementInjectionService.injectTrustStatements(metadata, ISSUER_DID);

        CredentialConfiguration config = metadata.getCredentialConfigurationSupported().get("TestFormat");
        assertThat(config.getProtectedIssuanceAuthorizationTrustStatement()).isNull();
    }

    @Test
    void injectTrustStatements_injectsCorrectPiaTs_perVct_whenMultipleConfigsPresent() throws Exception {
        String elfaPiaTs = buildPiaTsJwt(VCT_ELFA);
        String mdlPiaTs = buildPiaTsJwt(VCT_MDL);
        when(cacheService.getAllProtectedIssuanceAuthorizationTrustStatements(ISSUER_DID))
                .thenReturn(List.of(elfaPiaTs, mdlPiaTs));

        IssuerMetadata metadata = new IssuerMetadata();
        Map<String, CredentialConfiguration> configs = new HashMap<>();

        for (String vct : List.of(VCT_ELFA, VCT_MDL)) {
            CredentialConfiguration config = new CredentialConfiguration();
            config.setVct(vct);
            SupportedProofType proofType = new SupportedProofType();
            proofType.setKeyAttestationRequirement(KeyAttestationRequirement.builder()
                    .keyStorage(List.of(AttackPotentialResistance.ISO_18045_ENHANCED_BASIC))
                    .build());
            config.setProofTypesSupported(Map.of("jwt", proofType));
            configs.put(vct, config);
        }
        metadata.setCredentialConfigurationSupported(configs);

        trustStatementInjectionService.injectTrustStatements(metadata, ISSUER_DID);

        assertThat(metadata.getCredentialConfigurationSupported().get(VCT_ELFA)
                .getProtectedIssuanceAuthorizationTrustStatement()).isEqualTo(elfaPiaTs);
        assertThat(metadata.getCredentialConfigurationSupported().get(VCT_MDL)
                .getProtectedIssuanceAuthorizationTrustStatement()).isEqualTo(mdlPiaTs);
    }

    @Test
    void injectTrustStatements_withValidator_injectsWhenValidationPasses() throws Exception {
        String elfaPiaTs = buildPiaTsJwt(VCT_ELFA);
        when(cacheService.getIdentityTrustStatement(ISSUER_DID)).thenReturn(ID_TS);
        when(cacheService.getAllProtectedIssuanceAuthorizationTrustStatements(ISSUER_DID))
                .thenReturn(List.of(elfaPiaTs));

        IssuerMetadata metadata = createMetadata(true, VCT_ELFA);
        trustStatementInjectionService.injectTrustStatements(metadata, ISSUER_DID);

        verify(validator).validateSignature(ID_TS);
        verify(validator).validateSignature(elfaPiaTs);

        assertThat(metadata.getCredentialIssuerIdentityTrustStatement()).isEqualTo(ID_TS);
        assertThat(metadata.getCredentialConfigurationSupported().get("TestFormat")
                .getProtectedIssuanceAuthorizationTrustStatement()).isEqualTo(elfaPiaTs);
    }

    @Test
    void injectTrustStatements_withValidator_invalidatesCacheWhenValidationFails() throws Exception {
        String elfaPiaTs = buildPiaTsJwt(VCT_ELFA);
        when(cacheService.getIdentityTrustStatement(ISSUER_DID)).thenReturn(ID_TS);
        when(cacheService.getAllProtectedIssuanceAuthorizationTrustStatements(ISSUER_DID))
                .thenReturn(List.of(elfaPiaTs));

        doThrow(new JwtValidatorException("Invalid ID TS Signature")).when(validator).validateSignature(ID_TS);
        doThrow(new JwtValidatorException("Invalid PIA TS Signature")).when(validator).validateSignature(elfaPiaTs);

        IssuerMetadata metadata = createMetadata(true, VCT_ELFA);
        trustStatementInjectionService.injectTrustStatements(metadata, ISSUER_DID);

        verify(cacheService, times(2)).invalidateAllTrustStatements(ISSUER_DID); // once for idTS, once for piaTS

        assertThat(metadata.getCredentialIssuerIdentityTrustStatement()).isNull();
        assertThat(metadata.getCredentialConfigurationSupported().get("TestFormat")
                .getProtectedIssuanceAuthorizationTrustStatement()).isNull();
    }
}
