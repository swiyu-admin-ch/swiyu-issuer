package ch.admin.bj.swiyu.issuer.service.dpop;

import static java.util.Objects.requireNonNull;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.apache.commons.lang3.StringUtils;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpRequest;
import org.springframework.http.server.ServletServerHttpRequest;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.DemonstratingProofOfPossessionException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialManagement;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialManagementRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferRepository;
import ch.admin.bj.swiyu.issuer.domain.openid.CachedNonceRepository;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.AttackPotentialResistance;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.IssuerSecret;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.IssuerSecretRepository;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.SelfContainedNonce;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialConfiguration;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.KeyAttestationRequirement;
import ch.admin.bj.swiyu.issuer.domain.openid.metadata.SupportedProofType;
import ch.admin.bj.swiyu.issuer.service.MetadataService;
import ch.admin.bj.swiyu.issuer.service.NonceService;
import ch.admin.bj.swiyu.issuer.service.OAuthService;
import ch.admin.bj.swiyu.issuer.service.credential.KeyAttestationService;

class DemonstratingProofOfPossessionServiceTest {
    public static final String DPOP_NONCE_HEADER = "DPoP-Nonce";
    private DemonstratingProofOfPossessionService demonstratingProofOfPossessionService;
    private ApplicationProperties applicationProperties;
    private NonceService nonceService;
    private OAuthService oAuthService;
    private CredentialOfferRepository credentialOfferRepository;
    private CredentialManagementRepository credentialManagementRepository;
    private ECKey dpopKey;
    private IssuerSecret nonceSecret;
    private MetadataService metadataService;

    @BeforeEach
    void setUp() {
        applicationProperties = Mockito.mock(ApplicationProperties.class);
        credentialOfferRepository = Mockito.mock(CredentialOfferRepository.class);
        credentialManagementRepository = Mockito.mock(CredentialManagementRepository.class);
        CachedNonceRepository cachedNonceRepository = Mockito.mock(CachedNonceRepository.class);
        IssuerSecretRepository nonceSecretRepository = Mockito.mock(IssuerSecretRepository.class);
        nonceService = new NonceService(applicationProperties, cachedNonceRepository, nonceSecretRepository);
        oAuthService = Mockito.mock(OAuthService.class);
        KeyAttestationService keyAttestationService = Mockito.mock(KeyAttestationService.class);
        metadataService = Mockito.mock(MetadataService.class);
        demonstratingProofOfPossessionService = new DemonstratingProofOfPossessionService(
                applicationProperties,
                nonceService,
                oAuthService,
                credentialOfferRepository,
                credentialManagementRepository,
                new DemonstratingProofOfPossessionValidationService(applicationProperties, nonceService),
                metadataService,
                keyAttestationService

        );
        dpopKey = assertDoesNotThrow(() -> new ECKeyGenerator(Curve.P_256)
                .keyID("HolderDPoPKey")
                .keyUse(KeyUse.SIGNATURE)
                .generate());

        when(applicationProperties.getNonceLifetimeSeconds()).thenReturn(10);
        when(applicationProperties.getAcceptableProofTimeWindowSeconds()).thenReturn(10);
        when(applicationProperties.getExternalUrl()).thenReturn("https://www.example.com");
        nonceSecret = IssuerSecret.builder().id(UUID.randomUUID()).build();
        when(nonceSecretRepository.findAll()).thenReturn(List.of(nonceSecret));
    }

    @Test
    void testAddDpopNonceHeader() {
        var httpHeader = new HttpHeaders();
        assertThat(httpHeader.isEmpty()).isTrue();
        demonstratingProofOfPossessionService.addDpopNonce(httpHeader);
        assertThat(httpHeader.isEmpty()).isFalse();
        assertThat(httpHeader.containsHeader(DPOP_NONCE_HEADER)).isTrue();
        assertThat(httpHeader.get(DPOP_NONCE_HEADER)).isNotEmpty().hasSize(1);
        var nonce = requireNonNull(httpHeader.getFirst(DPOP_NONCE_HEADER));
        var dPopNonce = assertDoesNotThrow(() -> new SelfContainedNonce(nonce, applicationProperties.getNonceLifetimeSeconds(), nonceSecret));
        Assertions.assertThat(nonceService.isUsedNonce(dPopNonce)).isFalse();
    }

    /**
     * Test for the inintial registration of the DPoP, done when calling the token endpoint
     */
    @Test
    void testRegisterDemonstratingProofOfPossession_thenSuccess() {
        var request = Mockito.mock(HttpRequest.class);
        var requestUri = assertDoesNotThrow(() -> new URI("https://www.example.com/token?debug"));
        var preAuthCode = UUID.randomUUID();
        var mgmt = Mockito.mock(CredentialManagement.class);
        var offer = Mockito.mock(CredentialOffer.class);

        when(offer.getCredentialManagement()).thenReturn(mgmt);

        when(request.getMethod()).thenReturn(HttpMethod.POST);
        when(request.getURI()).thenReturn(requestUri);
        when(credentialOfferRepository.findByPreAuthorizedCode(any())).thenReturn(Optional.of(offer));

        var dpop = createDpopJwt(HttpMethod.POST.name(), "https://www.example.com/token", null, dpopKey);
        assertDoesNotThrow(() -> demonstratingProofOfPossessionService.registerDpop(preAuthCode.toString(), signAndSerialize(dpop, dpopKey), request));
    }

    /**
     * Test for validating the dpop provided in the header in a call with a valid bearer authentication token
     */
    @Test
    void testValidateDpop_thenSuccess() {
        var request = Mockito.mock(HttpRequest.class);
        var requestUri = assertDoesNotThrow(() -> new URI("https://www.example.com/credential?debug"));
        var accessToken = UUID.randomUUID();
        when(request.getMethod()).thenReturn(HttpMethod.POST);
        when(request.getURI()).thenReturn(requestUri);
        var mockManagement = Mockito.mock(CredentialManagement.class);
        when(oAuthService.getCredentialManagementByAccessToken(accessToken.toString())).thenReturn(mockManagement);
        when(mockManagement.getDpopKey()).thenReturn(dpopKey.toPublicJWK().toJSONObject());

        var dpop = createDpopJwt(HttpMethod.POST.name(), "https://www.example.com/credential", accessToken.toString(), dpopKey);
        assertDoesNotThrow(() -> demonstratingProofOfPossessionService.validateDpop(accessToken.toString(), signAndSerialize(dpop, dpopKey), request));
    }

    @Test
    void testValidateDpop_whenSwissProfileVersioningEnforced_thenProfileVersionRequired() {
        when(applicationProperties.isSwissProfileVersioningEnforcement()).thenReturn(true);

        var request = Mockito.mock(HttpRequest.class);
        var requestUri = assertDoesNotThrow(() -> new URI("https://www.example.com/token?debug"));
        when(request.getMethod()).thenReturn(HttpMethod.POST);
        when(request.getURI()).thenReturn(requestUri);

        var mgmt = Mockito.mock(CredentialManagement.class);
        var offer = Mockito.mock(CredentialOffer.class);
        when(offer.getCredentialManagement()).thenReturn(mgmt);
        when(credentialOfferRepository.findByPreAuthorizedCode(any())).thenReturn(Optional.of(offer));

        // Without profile_version -> should fail when enforcement enabled
        var dpopWithoutProfileVersion = createDpopJwt(HttpMethod.POST.name(), "https://www.example.com/token", null, dpopKey, false);
        var failingCall = (org.junit.jupiter.api.function.Executable) () -> demonstratingProofOfPossessionService.registerDpop(
                UUID.randomUUID().toString(),
                signAndSerialize(dpopWithoutProfileVersion, dpopKey),
                request);
        assertThrows(DemonstratingProofOfPossessionException.class, failingCall);

        // With profile_version -> should pass
        var dpopWithProfileVersion = createDpopJwt(HttpMethod.POST.name(), "https://www.example.com/token", null, dpopKey, true);
        assertDoesNotThrow(() -> demonstratingProofOfPossessionService.registerDpop(UUID.randomUUID().toString(),
                signAndSerialize(dpopWithProfileVersion, dpopKey),
                request));
    }


    /**
     * Downgrading would be when no DPoP is provided but previously DPoP was used.
     * This is not allowed.
     */
    @Test
    void testValidateDpop_whenDowngrading_throwsException() {
        var request = Mockito.mock(HttpRequest.class);
        var accessToken = UUID.randomUUID().toString();
        var mockManagement = Mockito.mock(CredentialManagement.class);
        // DPoP enforcement is disabled (optional) – the exception is still expected because a key was previously registered
        when(applicationProperties.isDpopEnforce()).thenReturn(false);
        // Simulate that a DPoP key has already been registered for this credential management
        when(mockManagement.hasDPoPKey()).thenReturn(true);
        when(oAuthService.getCredentialManagementByAccessToken(accessToken)).thenReturn(mockManagement);

        assertThrows(DemonstratingProofOfPossessionException.class, () -> demonstratingProofOfPossessionService.validateDpop(accessToken, null, request));
    }

    @Test
    void testRefreshDpop_whenDowngrading_throwsException() {
        var request = Mockito.mock(ServletServerHttpRequest.class);
        var refreshToken = UUID.randomUUID().toString();

        var mockManagement = Mockito.mock(CredentialManagement.class);
        // Simulate that a DPoP key has already been registered for this credential management
        when(mockManagement.hasDPoPKey()).thenReturn(true);

        // DPoP enforcement is disabled (optional) – the exception is still expected because a key was previously registered
        when(applicationProperties.isDpopEnforce()).thenReturn(false);
        when(oAuthService.getUnrevokedCredentialOfferByRefreshToken(refreshToken))
        .thenReturn(mockManagement);
        
        assertThrows(DemonstratingProofOfPossessionException.class,
            () -> demonstratingProofOfPossessionService.refreshDpop(refreshToken, null, request));
        }
        

  @Test
    void requiresKeyAttestation_nullSupportedId() {
        // CredentialOffer returns null for supported credential IDs
        var offer = Mockito.mock(CredentialOffer.class);
        when(offer.getMetadataCredentialSupportedId()).thenReturn(null);
        // No interaction with metadataService should be needed
        boolean result = assertDoesNotThrow(() -> demonstratingProofOfPossessionService.requiresKeyAttestation(offer));
        assertThat(result).isFalse();
    }

    @Test
    void requiresKeyAttestation_noKeyAttestationDefined() {
        // Create one mock where no requirement is defined (is null)
        var offer = Mockito.mock(CredentialOffer.class);
        when(offer.getMetadataCredentialSupportedId()).thenReturn(List.of("cred1"));
        // Mock IssuerMetadata and CredentialConfiguration without key attestation
        var issuerMetadata = Mockito.mock(ch.admin.bj.swiyu.issuer.domain.openid.metadata.IssuerMetadata.class);
        var credConfig = Mockito.mock(ch.admin.bj.swiyu.issuer.domain.openid.metadata.CredentialConfiguration.class);
        when(metadataService.getUnsignedIssuerMetadata()).thenReturn(issuerMetadata);
        when(issuerMetadata.getCredentialConfigurationById("cred1")).thenReturn(credConfig);
        // proofTypesSupported map with a SupportedProofType having null keyAttestationRequirement
        var supportedProofType = new ch.admin.bj.swiyu.issuer.domain.openid.metadata.SupportedProofType();
        supportedProofType.setKeyAttestationRequirement(null);
        when(credConfig.getProofTypesSupported()).thenReturn(Map.of("jwt", supportedProofType));

        boolean result = assertDoesNotThrow(() -> demonstratingProofOfPossessionService.requiresKeyAttestation(offer));
        assertThat(result).isFalse();
    }

    @Test
    void requiresKeyAttestation_keyAttestationWithoutHigh() {
        // Create one mock with low requirement
        var offer = Mockito.mock(CredentialOffer.class);
        when(offer.getMetadataCredentialSupportedId()).thenReturn(List.of("cred1"));
        var issuerMetadata = Mockito.mock(IssuerMetadata.class);
        var credConfig = Mockito.mock(CredentialConfiguration.class);
        when(metadataService.getUnsignedIssuerMetadata()).thenReturn(issuerMetadata);
        when(issuerMetadata.getCredentialConfigurationById("cred1")).thenReturn(credConfig);
        var keyAttReq = KeyAttestationRequirement.builder()
                .keyStorage(List.of(AttackPotentialResistance.ISO_18045_ENHANCED_BASIC))
                .build();
        var supportedProofType = new SupportedProofType();
        supportedProofType.setKeyAttestationRequirement(keyAttReq);
        when(credConfig.getProofTypesSupported()).thenReturn(Map.of("jwt", supportedProofType));

        boolean result = assertDoesNotThrow(() -> demonstratingProofOfPossessionService.requiresKeyAttestation(offer));
        assertThat(result).isTrue();
    }

    @Test
    void requiresKeyAttestation_keyAttestationWithHigh() {
        // Create 1 Mock with high requirement
        var offer = Mockito.mock(CredentialOffer.class);
        when(offer.getMetadataCredentialSupportedId()).thenReturn(List.of("cred1"));
        var issuerMetadata = Mockito.mock(IssuerMetadata.class);
        var credConfig = Mockito.mock(CredentialConfiguration.class);
        when(metadataService.getUnsignedIssuerMetadata()).thenReturn(issuerMetadata);
        when(issuerMetadata.getCredentialConfigurationById("cred1")).thenReturn(credConfig);
        var keyAttReq = ch.admin.bj.swiyu.issuer.domain.openid.metadata.KeyAttestationRequirement.builder()
                .keyStorage(List.of(AttackPotentialResistance.ISO_18045_HIGH))
                .build();
        var supportedProofType = new SupportedProofType();
        supportedProofType.setKeyAttestationRequirement(keyAttReq);
        when(credConfig.getProofTypesSupported()).thenReturn(Map.of("jwt", supportedProofType));

        boolean result = assertDoesNotThrow(() -> demonstratingProofOfPossessionService.requiresKeyAttestation(offer));
        assertThat(result).isTrue();
    }

    @Test
    void requiresKeyAttestation_multipleCredentialsOneRequiresHigh() {
        // Create Mocks with 2 offered Credentials. one with high one with low attestation requirement
        var offer = Mockito.mock(CredentialOffer.class);
        when(offer.getMetadataCredentialSupportedId()).thenReturn(List.of("cred1", "cred2"));
        var issuerMetadata = Mockito.mock(IssuerMetadata.class);
        var credConfig1 = Mockito.mock(CredentialConfiguration.class);
        var credConfig2 = Mockito.mock(CredentialConfiguration.class);
        when(metadataService.getUnsignedIssuerMetadata()).thenReturn(issuerMetadata);
        when(issuerMetadata.getCredentialConfigurationById("cred1")).thenReturn(credConfig1);
        when(issuerMetadata.getCredentialConfigurationById("cred2")).thenReturn(credConfig2);
        // cred1 has no high requirement
        var basicProofType = SupportedProofType.builder().keyAttestationRequirement(
            KeyAttestationRequirement.builder().keyStorage(List.of(AttackPotentialResistance.ISO_18045_ENHANCED_BASIC)
        ).build()).build();
        when(credConfig1.getProofTypesSupported()).thenReturn(Map.of("jwt", basicProofType));
        // cred2 has high requirement
        var highProofType = SupportedProofType.builder().keyAttestationRequirement(
            KeyAttestationRequirement.builder().keyStorage(List.of(AttackPotentialResistance.ISO_18045_HIGH)
        ).build()).build();
        when(credConfig2.getProofTypesSupported()).thenReturn(Map.of("jwt", highProofType));
        // Then
        boolean result = assertDoesNotThrow(() -> demonstratingProofOfPossessionService.requiresKeyAttestation(offer));
        assertThat(result).isTrue();
    }

    @Test
    void validateDPoPKeyAttestation_whenNoKeyAttestation_throwsDemonstratingProofOfPossessionException() {
        var headerBuilder = new JWSHeader.Builder(JWSAlgorithm.ES256);
        var emptyBody = new JWTClaimsSet.Builder().build();
        // Test with completely missing header
        var emptyJWT = new SignedJWT(headerBuilder.build(), emptyBody);
        assertThrows(DemonstratingProofOfPossessionException.class, 
            () -> demonstratingProofOfPossessionService.validateDPoPKeyAttestation(emptyJWT));
        
        var nullAttestationJWT = new SignedJWT(
            headerBuilder.customParam(DemonstratingProofOfPossessionService.DPOP_KEY_ATTESTATION_CLAIM, null).build(), 
            emptyBody);
        assertThrows(DemonstratingProofOfPossessionException.class, 
            () -> demonstratingProofOfPossessionService.validateDPoPKeyAttestation(nullAttestationJWT));
    }

    private SignedJWT createDpopJwt(String httpMethod, String httpUri, String accessToken, ECKey dpopKey) {
        return createDpopJwt(httpMethod, httpUri, accessToken, dpopKey, true);
    }

    private SignedJWT createDpopJwt(String httpMethod, String httpUri, String accessToken, ECKey dpopKey, boolean includeProfileVersion) {
        // Fetch a fresh nonce
        var httpHeader = new HttpHeaders();
        demonstratingProofOfPossessionService.addDpopNonce(httpHeader);
        var dpopNonce = assertDoesNotThrow(() -> requireNonNull(httpHeader.getFirst(DPOP_NONCE_HEADER)));

        // Create a DPoP JWT
        var claimSetBuilder = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .issueTime(new Date())
                .claim("htm", httpMethod)
                .claim("htu", httpUri)
                .claim("nonce", dpopNonce);
        if (StringUtils.isNotEmpty(accessToken)) {
            claimSetBuilder.claim("ath", Base64.getUrlEncoder().encodeToString(assertDoesNotThrow(() -> MessageDigest.getInstance("SHA-256")).digest(accessToken.getBytes(StandardCharsets.UTF_8))));
        }

        var headerBuilder = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .jwk(dpopKey.toPublicJWK())
                .type(new JOSEObjectType("dpop+jwt"));
        if (includeProfileVersion) {
            headerBuilder.customParam("profile_version", "swiss-profile-issuance:1.0.0");
        }
        return new SignedJWT(headerBuilder.build(), claimSetBuilder.build());
    }


    private String signAndSerialize(SignedJWT signedJwt, ECKey dpopKey) {
        assertDoesNotThrow(() -> signedJwt.sign(new ECDSASigner(dpopKey)));
        return signedJwt.serialize();
    }


}