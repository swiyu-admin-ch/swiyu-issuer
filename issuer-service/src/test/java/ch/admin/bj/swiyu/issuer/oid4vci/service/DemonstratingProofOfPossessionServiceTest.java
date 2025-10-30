package ch.admin.bj.swiyu.issuer.oid4vci.service;

import ch.admin.bj.swiyu.issuer.common.config.ApplicationProperties;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferRepository;
import ch.admin.bj.swiyu.issuer.domain.openid.CachedNonceRepository;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.SelfContainedNonce;
import ch.admin.bj.swiyu.issuer.service.DemonstratingProofOfPossessionService;
import ch.admin.bj.swiyu.issuer.service.DemonstratingProofOfPossessionValidationService;
import ch.admin.bj.swiyu.issuer.service.NonceService;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class DemonstratingProofOfPossessionServiceTest {
    public static final String DPOP_NONCE_HEADER = "DPoP-Nonce";
    private DemonstratingProofOfPossessionService demonstratingProofOfPossessionService;
    private ApplicationProperties applicationProperties;
    private NonceService nonceService;
    private CredentialOfferRepository credentialOfferRepository;
    private ECKey dpopKey;

    @BeforeEach
    void setUp() {
        applicationProperties = Mockito.mock(ApplicationProperties.class);
        credentialOfferRepository = Mockito.mock(CredentialOfferRepository.class);
        CachedNonceRepository cachedNonceRepository = Mockito.mock(CachedNonceRepository.class);
        nonceService = new NonceService(applicationProperties, cachedNonceRepository);
        demonstratingProofOfPossessionService = new DemonstratingProofOfPossessionService(
                applicationProperties,
                nonceService,
                credentialOfferRepository,
                new DemonstratingProofOfPossessionValidationService(applicationProperties)
        );
        dpopKey = assertDoesNotThrow(() -> new ECKeyGenerator(Curve.P_256)
                .keyID("HolderDPoPKey")
                .keyUse(KeyUse.SIGNATURE)
                .generate());

        Mockito.when(applicationProperties.getNonceLifetimeSeconds()).thenReturn(10);
        Mockito.when(applicationProperties.getExternalUrl()).thenReturn("https://www.example.com");
    }

    @Test
    void testAddDpopNonceHeader() {
        var httpHeader = new HttpHeaders();
        assertThat(httpHeader).isEmpty();
        demonstratingProofOfPossessionService.addDpopNonce(httpHeader);
        assertThat(httpHeader).isNotEmpty().containsKey(DPOP_NONCE_HEADER);
        assertThat(httpHeader.get(DPOP_NONCE_HEADER)).isNotEmpty().hasSize(1);
        var dPopNonce = new SelfContainedNonce(httpHeader.get(DPOP_NONCE_HEADER).getFirst());
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
        Mockito.when(request.getMethod()).thenReturn(HttpMethod.POST);
        Mockito.when(request.getURI()).thenReturn(requestUri);
        Mockito.when(credentialOfferRepository.findByPreAuthorizedCode(preAuthCode)).thenReturn(Optional.of(Mockito.mock(CredentialOffer.class)));

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
        Mockito.when(request.getMethod()).thenReturn(HttpMethod.POST);
        Mockito.when(request.getURI()).thenReturn(requestUri);
        var mockOffer = Mockito.mock(CredentialOffer.class);
        Mockito.when(credentialOfferRepository.findByAccessToken(accessToken)).thenReturn(Optional.of(mockOffer));
        Mockito.when(mockOffer.getDpopKey()).thenReturn(dpopKey.toPublicJWK().toJSONObject());

        var dpop = createDpopJwt(HttpMethod.POST.name(), "https://www.example.com/credential", accessToken.toString(), dpopKey);
        assertDoesNotThrow(() -> demonstratingProofOfPossessionService.validateDpop(accessToken.toString(), signAndSerialize(dpop, dpopKey), request));
    }


    private SignedJWT createDpopJwt(String httpMethod, String httpUri, String accessToken, ECKey dpopKey) {
        // Fetch a fresh nonce
        var httpHeader = new HttpHeaders();
        demonstratingProofOfPossessionService.addDpopNonce(httpHeader);
        var dpopNonce = assertDoesNotThrow(() -> httpHeader.get(DPOP_NONCE_HEADER).getFirst());
        // Create a DPoP JWT
        var claimSetBuilder = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .issueTime(new Date())
                .claim("htm", httpMethod)
                .claim("htu", httpUri)
                .claim("nonce", dpopNonce);
        if (StringUtils.isNotEmpty(accessToken)) {
            claimSetBuilder.claim("ath", Base64.getEncoder().encodeToString(assertDoesNotThrow(() -> MessageDigest.getInstance("SHA-256")).digest(accessToken.getBytes(StandardCharsets.UTF_8))));
        }
        return new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256)
                .jwk(dpopKey.toPublicJWK())
                .type(new JOSEObjectType("dpop+jwt"))
                .build(),
                claimSetBuilder.build());
    }


    private String signAndSerialize(SignedJWT signedJwt, ECKey dpopKey) {
        assertDoesNotThrow(() -> signedJwt.sign(new ECDSASigner(dpopKey)));
        return signedJwt.serialize();
    }


}
