package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.UrlRewriteProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;

import java.util.NoSuchElementException;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import static org.junit.jupiter.api.Assertions.*;


public class DidKeyResolverTest {
    private UrlRewriteProperties urlRewriteProperties;
    private DidKeyResolverApiClient didKeyResolverApiClient;
    private DidKeyResolver didKeyResolver;

    private final String didWebvhId = "did:webvh:QmXjVQdrbmDjrKXftYvkqXaueeKUYjVzQfnzcM5bTNwNod:example.com:webvh";
    private final String didTdwId = "did:tdw:QmUBfEWAQpZ9SbjoSSsRUgibgvHv9w3cvjWfaRFAqixJg4:example.com:tdw";

    @BeforeEach
    void setUp() {
        var objectMapper = new ObjectMapper();

        var urlRewriteProperties = mock(UrlRewriteProperties.class);
        when(urlRewriteProperties.getRewrittenUrl(anyString())).thenAnswer(i -> i.getArguments()[0]);

        var didKeyResolverApiClient = mock(DidKeyResolverApiClient.class);
        String validDidWebvhLog = "{\"versionId\":\"1-QmV3sVnrmcZ1ruCpLD6dsoUihC7ZcYNc7MMjG2WFMEJTWD\",\"versionTime\":\"2025-10-28T12:15:47Z\",\"parameters\":{\"method\":\"did:webvh:1.0\",\"scid\":\"QmXjVQdrbmDjrKXftYvkqXaueeKUYjVzQfnzcM5bTNwNod\",\"updateKeys\":[\"z6Mknx43YpVwFcCr54B2rGr1peaGXW96D3ADANZNFLEUX1q5\"],\"portable\":false},\"state\":{\"@context\":[\"https://www.w3.org/ns/did/v1\",\"https://w3id.org/security/jwk/v1\"],\"id\":\"did:webvh:QmXjVQdrbmDjrKXftYvkqXaueeKUYjVzQfnzcM5bTNwNod:example.com:webvh\",\"authentication\":[\"did:webvh:QmXjVQdrbmDjrKXftYvkqXaueeKUYjVzQfnzcM5bTNwNod:example.com:webvh#auth-key-01\"],\"assertionMethod\":[\"did:webvh:QmXjVQdrbmDjrKXftYvkqXaueeKUYjVzQfnzcM5bTNwNod:example.com:webvh#assert-key-01\"],\"verificationMethod\":[{\"id\":\"did:webvh:QmXjVQdrbmDjrKXftYvkqXaueeKUYjVzQfnzcM5bTNwNod:example.com:webvh#auth-key-01\",\"type\":\"JsonWebKey2020\",\"publicKeyJwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"f-ushacD2MV5OLD28ci93Y4e9opdjccxFom3dXLNzxk\",\"y\":\"TWli99af6w00BY6nau5Ov0Ulj9RnAbsqZQecxkWxI4A\",\"kid\":\"auth-key-01\"}},{\"id\":\"did:webvh:QmXjVQdrbmDjrKXftYvkqXaueeKUYjVzQfnzcM5bTNwNod:example.com:webvh#assert-key-01\",\"type\":\"JsonWebKey2020\",\"publicKeyJwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"EdydVEB5tCh30ykAM9DWiB4DpWcl_ojJlWRFVqULEL4\",\"y\":\"F3alaKXwPg5JSK1smVNhgIv1tErYHmNdcvCW4KpKY-w\",\"kid\":\"assert-key-01\"}}]},\"proof\":[{\"type\":\"DataIntegrityProof\",\"cryptosuite\":\"eddsa-jcs-2022\",\"created\":\"2025-10-28T12:15:47Z\",\"verificationMethod\":\"did:key:z6Mknx43YpVwFcCr54B2rGr1peaGXW96D3ADANZNFLEUX1q5#z6Mknx43YpVwFcCr54B2rGr1peaGXW96D3ADANZNFLEUX1q5\",\"proofPurpose\":\"assertionMethod\",\"proofValue\":\"zRwiS81J4Jk3GGVNKYiker2PQa5WgeEne1mEbWEyuY1UYivXxTsFEPDYo5MhzccGxehihiDLkBKEgVfLGtexJVWB\"}]}";
        when(didKeyResolverApiClient.fetchDidLog(contains("example.com/webvh"))).thenReturn(validDidWebvhLog);
        String validDidTdwLog = "[\"1-QmbSsqpCBygwgxjL9aUsBuvgaTkxKvEqEVKEWnDTjje2bN\",\"2025-10-28T12:16:58Z\",{\"method\":\"did:tdw:0.3\",\"scid\":\"QmUBfEWAQpZ9SbjoSSsRUgibgvHv9w3cvjWfaRFAqixJg4\",\"updateKeys\":[\"z6MkgJMiHsaWrznGWtULiLauWf5wYxfhUFRNJD6oMaVVrnhq\"],\"portable\":false},{\"value\":{\"@context\":[\"https://www.w3.org/ns/did/v1\",\"https://w3id.org/security/jwk/v1\"],\"id\":\"did:tdw:QmUBfEWAQpZ9SbjoSSsRUgibgvHv9w3cvjWfaRFAqixJg4:example.com:tdw\",\"authentication\":[\"did:tdw:QmUBfEWAQpZ9SbjoSSsRUgibgvHv9w3cvjWfaRFAqixJg4:example.com:tdw#auth-key-01\"],\"assertionMethod\":[\"did:tdw:QmUBfEWAQpZ9SbjoSSsRUgibgvHv9w3cvjWfaRFAqixJg4:example.com:tdw#assert-key-01\"],\"verificationMethod\":[{\"id\":\"did:tdw:QmUBfEWAQpZ9SbjoSSsRUgibgvHv9w3cvjWfaRFAqixJg4:example.com:tdw#auth-key-01\",\"type\":\"JsonWebKey2020\",\"publicKeyJwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"mQkqapaMiA1brcmn8o10DgrDIAamt8g30n0NchcxBxE\",\"y\":\"88JCGM_JwTlkd9O0ntO-EKVCIfHK7CXSAT8ac-Z99ns\",\"kid\":\"auth-key-01\"}},{\"id\":\"did:tdw:QmUBfEWAQpZ9SbjoSSsRUgibgvHv9w3cvjWfaRFAqixJg4:example.com:tdw#assert-key-01\",\"type\":\"JsonWebKey2020\",\"publicKeyJwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"P0xXpYzcIXByGjS5MK_Rn74ATxZ8uIgnpcWXFA3NVDw\",\"y\":\"x0xMtVARt0DJb9092zQcjpitp6RLf5nXyOsst93yC00\",\"kid\":\"assert-key-01\"}}]}},[{\"type\":\"DataIntegrityProof\",\"cryptosuite\":\"eddsa-jcs-2022\",\"created\":\"2025-10-28T12:16:58Z\",\"verificationMethod\":\"did:key:z6MkgJMiHsaWrznGWtULiLauWf5wYxfhUFRNJD6oMaVVrnhq#z6MkgJMiHsaWrznGWtULiLauWf5wYxfhUFRNJD6oMaVVrnhq\",\"proofPurpose\":\"authentication\",\"challenge\":\"1-QmbSsqpCBygwgxjL9aUsBuvgaTkxKvEqEVKEWnDTjje2bN\",\"proofValue\":\"z394DdiHbHVAqSZtHnKm1JsoM7xXYm6LGztTrwcaPbJREdqHD3sTLEW4kWwPSdJzwmRfKjKS2UuQAGW2zy7wyF67D\"}]]";
        when(didKeyResolverApiClient.fetchDidLog(contains("example.com/tdw"))).thenReturn(validDidTdwLog);

        didKeyResolver = new DidKeyResolver(objectMapper, urlRewriteProperties, didKeyResolverApiClient);
    }

    @Test
    public void testResolveKey_didWebvh_thenSuccess() {
        var fragment  = "assert-key-01";
        var key = didWebvhId + "#" + fragment;
        var jwk = didKeyResolver.resolveKey(key);
        assertEquals(fragment, jwk.getKeyID());
    }

    @Test
    public void testResolveKey_didTdw_thenSuccess() {
        var fragment  = "assert-key-01";
        var key = didTdwId + "#" + fragment;
        var jwk = didKeyResolver.resolveKey(key);
        assertEquals(fragment, jwk.getKeyID());
    }

    @Test
    public void testResolveKey_missingJwk_throwsExeception() {
        var fragment  = "jwk-not-in-did";
        var key = didTdwId + "#" + fragment;
        assertThrows(NoSuchElementException.class, () -> didKeyResolver.resolveKey(key));
    }

    @Test
    public void testResolveDidTdw_invalidKey_throwsException() {
        var key = didWebvhId;
        assertThrows(IllegalArgumentException.class, () -> didKeyResolver.resolveKey(key));
    }
}
