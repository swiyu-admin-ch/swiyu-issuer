package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.common.config.UrlRewriteProperties;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.KeyResolver;
import ch.admin.eid.did_sidekicks.DidSidekicksException;
import ch.admin.eid.did_sidekicks.Jwk;
import ch.admin.eid.didresolver.Did;
import ch.admin.eid.didresolver.DidResolveException;
import ch.admin.eid.did_sidekicks.DidDoc;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWK;
import lombok.AllArgsConstructor;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.util.NoSuchElementException;

import static ch.admin.bj.swiyu.issuer.common.config.CacheConfig.PUBLIC_KEY_CACHE;

@Service
@AllArgsConstructor
public class DidKeyResolver implements KeyResolver {
    private final ObjectMapper objectMapper;
    private final UrlRewriteProperties urlRewriteProperties;
    private final DidKeyResolverApiClient didKeyResolverApiClient;

    /**
     * @param keyId full did:tdw/did:webvh including #fragment indicating the verification method
     * @return JWK fetched from the did document
     */
    @Override
    @Cacheable(PUBLIC_KEY_CACHE)
    public JWK resolveKey(String keyId) {
        var didLog = fetchDidLog(keyId);
        DidDoc didDoc = getDidDoc(keyId, didLog);

        var keySplit = keyId.split("#");
        if (keySplit.length != 2) {
            throw new IllegalArgumentException(String.format("Key %s is malformed: missing fragment", keyId));
        }

        try {
            var jwk = didDoc.getKey(keySplit[1]);
            return didResolverJwkToNimbusJwk(jwk);
        } catch (DidSidekicksException e) {
            throw new NoSuchElementException("No value present");
        } catch (JsonProcessingException | ParseException e) {
            throw new IllegalArgumentException(String.format("Verification Method %s is malformed", keyId), e);
        }
    }

    private String fetchDidLog(String keyId) {
        try (var did = new Did(keyId)) {
            System.out.println(did.getUrl());
            var url = urlRewriteProperties.getRewrittenUrl(did.getUrl());
            // Fetch the did log; throw RestClientResponseException if status >=400
            return didKeyResolverApiClient.fetchDidLog(url);
        } catch (DidResolveException e) {
            throw new IllegalArgumentException("DID Document could not be fetched", e);
        }
    }

    private DidDoc getDidDoc(String keyId, String didLog) {
        DidDoc didDoc;
        try (Did did = new Did(keyId)){
            didDoc = did.resolve(didLog);
        } catch (DidResolveException e) {
            throw new IllegalArgumentException("DID Document could not be loaded", e);
        }
        return didDoc;
    }

    private JWK didResolverJwkToNimbusJwk(Jwk resolverJwk) throws JsonProcessingException, ParseException {
        var jwkString = objectMapper.writeValueAsString(resolverJwk);
        return JWK.parse(jwkString);
    }
}