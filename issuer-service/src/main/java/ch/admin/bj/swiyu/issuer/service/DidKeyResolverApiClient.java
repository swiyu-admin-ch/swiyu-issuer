package ch.admin.bj.swiyu.issuer.service;

import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.net.URI;

@Service
@AllArgsConstructor
public class DidKeyResolverApiClient {

    private final RestClient restClient;

    public String fetchDidLog(String url) {
        // This method should implement the logic to fetch the DID log based on the keyId.
        // For now, it returns a placeholder string.
        return restClient.get().uri(URI.create(url)).retrieve().body(String.class);
    }
}