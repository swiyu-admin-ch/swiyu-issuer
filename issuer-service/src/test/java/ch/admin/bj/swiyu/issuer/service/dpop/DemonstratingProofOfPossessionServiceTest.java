package ch.admin.bj.swiyu.issuer.service.dpop;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.common.exception.DemonstratingProofOfPossessionException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialManagement;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialManagementRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferRepository;
import ch.admin.bj.swiyu.issuer.domain.openid.CachedNonceRepository;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.SelfContainedNonce;
import ch.admin.bj.swiyu.issuer.service.NonceService;
import ch.admin.bj.swiyu.issuer.service.OAuthService;
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
import org.apache.commons.lang3.StringUtils;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpRequest;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

import static java.util.Objects.requireNonNull;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

class DemonstratingProofOfPossessionServiceTest {
    public static final String DPOP_NONCE_HEADER = "DPoP-Nonce";
    private DemonstratingProofOfPossessionService demonstratingProofOfPossessionService;
    private ApplicationProperties applicationProperties;
    private NonceService nonceService;
    private OAuthService oAuthService;
    private CredentialOfferRepository credentialOfferRepository;
    private CredentialManagementRepository credentialManagementRepository;
    private ECKey dpopKey;

    @BeforeEach
    void setUp() {
        applicationProperties = Mockito.mock(ApplicationProperties.class);
        credentialOfferRepository = Mockito.mock(CredentialOfferRepository.class);
        credentialManagementRepository = Mockito.mock(CredentialManagementRepository.class);
        CachedNonceRepository cachedNonceRepository = Mockito.mock(CachedNonceRepository.class);
        nonceService = new NonceService(applicationProperties, cachedNonceRepository);
        oAuthService = Mockito.mock(OAuthService.class);
        demonstratingProofOfPossessionService = new DemonstratingProofOfPossessionService(
                applicationProperties,
                nonceService,
                oAuthService,
                credentialOfferRepository,
                credentialManagementRepository,
                new DemonstratingProofOfPossessionValidationService(applicationProperties, nonceService)
        );
        dpopKey = assertDoesNotThrow(() -> new ECKeyGenerator(Curve.P_256)
                .keyID("HolderDPoPKey")
                .keyUse(KeyUse.SIGNATURE)
                .generate());

        when(applicationProperties.getNonceLifetimeSeconds()).thenReturn(10);
        when(applicationProperties.getAcceptableProofTimeWindowSeconds()).thenReturn(10);
        when(applicationProperties.getExternalUrl()).thenReturn("https://www.example.com");
    }

    @Test
    void testAddDpopNonceHeader() {
        var httpHeader = new HttpHeaders();
        assertThat(httpHeader).isEmpty();
        demonstratingProofOfPossessionService.addDpopNonce(httpHeader);
        assertThat(httpHeader).isNotEmpty().containsKey(DPOP_NONCE_HEADER);
        assertThat(httpHeader.get(DPOP_NONCE_HEADER)).isNotEmpty().hasSize(1);
        var dPopNonce = new SelfContainedNonce(requireNonNull(httpHeader.getFirst(DPOP_NONCE_HEADER)));
        assertThat(dPopNonce.isSelfContainedNonce()).isTrue();
        assertThat(dPopNonce.isValid(applicationProperties.getNonceLifetimeSeconds())).isTrue();
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