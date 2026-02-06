package ch.admin.bj.swiyu.issuer.service.did;

import ch.admin.bj.swiyu.didresolveradapter.DidResolverAdapter;
import ch.admin.bj.swiyu.issuer.common.config.UrlRewriteProperties;
import ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding.KeyResolver;
import com.nimbusds.jose.jwk.JWK;
import lombok.AllArgsConstructor;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import static ch.admin.bj.swiyu.issuer.common.config.CacheConfig.PUBLIC_KEY_CACHE;

@Service
@AllArgsConstructor
public class DidKeyResolverFacade implements KeyResolver {

    private final DidResolverAdapter didResolverAdapter;
    private final UrlRewriteProperties urlRewriteProperties;

    /**
     * @param keyId full did:tdw/did:webvh including #fragment indicating the verification method
     * @return JWK fetched from the did document
     */
    @Override
    @Cacheable(PUBLIC_KEY_CACHE)
    public JWK resolveKey(String keyId) {
        return didResolverAdapter.resolveKey(keyId, urlRewriteProperties.getUrlMappings());
    }

}