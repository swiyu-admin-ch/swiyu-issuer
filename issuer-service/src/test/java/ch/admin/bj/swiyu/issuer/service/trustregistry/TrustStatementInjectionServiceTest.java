package ch.admin.bj.swiyu.issuer.service.trustregistry;

import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.AttackPotentialResistance;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialConfiguration;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.KeyAttestationRequirement;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.SupportedProofType;
import ch.admin.bj.swiyu.jwtvalidator.JwtValidatorException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class TrustStatementInjectionServiceTest {

    private TrustStatementCacheService cacheService;
    private TrustStatementValidator validator;
    private TrustStatementInjectionService serviceWithValidator;
    private TrustStatementInjectionService serviceWithoutValidator;

    private static final String ISSUER_DID = "did:tdw:test:issuer";
    private static final String ID_TS = "id.ts.jwt";
    private static final String PIA_TS = "pia.ts.jwt";

    @BeforeEach
    void setUp() {
        cacheService = mock(TrustStatementCacheService.class);
        validator = mock(TrustStatementValidator.class);
        serviceWithValidator = new TrustStatementInjectionService(cacheService, Optional.of(validator));
        serviceWithoutValidator = new TrustStatementInjectionService(cacheService, Optional.empty());
    }

    private IssuerMetadata createMetadata(boolean withProtectedVc) {
        IssuerMetadata metadata = new IssuerMetadata();
        Map<String, CredentialConfiguration> configs = new HashMap<>();

        CredentialConfiguration config = new CredentialConfiguration();
        Map<String, SupportedProofType> proofTypes = new HashMap<>();
        SupportedProofType proofType = new SupportedProofType();

        if (withProtectedVc) {
            var keyAttReq = KeyAttestationRequirement.builder()
                    .keyStorage(List.of(AttackPotentialResistance.ISO_18045_ENHANCED_BASIC))
                    .build();
            proofType.setKeyAttestationRequirement(keyAttReq); // non-null means protected
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

        IssuerMetadata metadata = createMetadata(false);
        serviceWithoutValidator.injectTrustStatements(metadata, ISSUER_DID);

        assertThat(metadata.getCredentialIssuerIdentityTrustStatement()).isEqualTo(ID_TS);
    }

    @Test
    void injectTrustStatements_doesNotInjectIdTs_whenNotInCache() {
        when(cacheService.getIdentityTrustStatement(ISSUER_DID)).thenReturn(null);

        IssuerMetadata metadata = createMetadata(false);
        serviceWithoutValidator.injectTrustStatements(metadata, ISSUER_DID);

        assertThat(metadata.getCredentialIssuerIdentityTrustStatement()).isNull();
    }

    @Test
    void injectTrustStatements_injectsPiaTs_forProtectedVcOnly() {
        when(cacheService.getProtectedIssuanceAuthorizationTrustStatement(ISSUER_DID)).thenReturn(PIA_TS);

        IssuerMetadata metadata = createMetadata(true);
        serviceWithoutValidator.injectTrustStatements(metadata, ISSUER_DID);

        CredentialConfiguration config = metadata.getCredentialConfigurationSupported().get("TestFormat");
        assertThat(config.getProtectedIssuanceAuthorizationTrustStatement()).isEqualTo(PIA_TS);
    }

    @Test
    void injectTrustStatements_doesNotInjectPiaTs_forNonProtectedVc() {
        when(cacheService.getProtectedIssuanceAuthorizationTrustStatement(ISSUER_DID)).thenReturn(PIA_TS);

        IssuerMetadata metadata = createMetadata(false);
        serviceWithoutValidator.injectTrustStatements(metadata, ISSUER_DID);

        CredentialConfiguration config = metadata.getCredentialConfigurationSupported().get("TestFormat");
        assertThat(config.getProtectedIssuanceAuthorizationTrustStatement()).isNull();
    }

    @Test
    void injectTrustStatements_withValidator_injectsWhenValidationPasses() {
        when(cacheService.getIdentityTrustStatement(ISSUER_DID)).thenReturn(ID_TS);
        when(cacheService.getProtectedIssuanceAuthorizationTrustStatement(ISSUER_DID)).thenReturn(PIA_TS);

        IssuerMetadata metadata = createMetadata(true);
        serviceWithValidator.injectTrustStatements(metadata, ISSUER_DID);

        verify(validator).validateSignature(ID_TS);
        verify(validator).validateSignature(PIA_TS);

        assertThat(metadata.getCredentialIssuerIdentityTrustStatement()).isEqualTo(ID_TS);
        assertThat(metadata.getCredentialConfigurationSupported().get("TestFormat").getProtectedIssuanceAuthorizationTrustStatement()).isEqualTo(PIA_TS);
    }

    @Test
    void injectTrustStatements_withValidator_invalidatesCacheWhenValidationFails() {
        when(cacheService.getIdentityTrustStatement(ISSUER_DID)).thenReturn(ID_TS);
        when(cacheService.getProtectedIssuanceAuthorizationTrustStatement(ISSUER_DID)).thenReturn(PIA_TS);

        doThrow(new JwtValidatorException("Invalid ID TS Signature")).when(validator).validateSignature(ID_TS);
        doThrow(new JwtValidatorException("Invalid PIA TS Signature")).when(validator).validateSignature(PIA_TS);

        IssuerMetadata metadata = createMetadata(true);
        serviceWithValidator.injectTrustStatements(metadata, ISSUER_DID);

        verify(cacheService, times(2)).invalidateAllTrustStatements(ISSUER_DID); // once for ID TS, once for PIA TS

        assertThat(metadata.getCredentialIssuerIdentityTrustStatement()).isNull();
        assertThat(metadata.getCredentialConfigurationSupported().get("TestFormat").getProtectedIssuanceAuthorizationTrustStatement()).isNull();
    }
}

