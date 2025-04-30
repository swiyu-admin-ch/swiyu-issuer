package ch.admin.bj.swiyu.issuer.oid4vci.service;

import ch.admin.bj.swiyu.issuer.oid4vci.domain.openid.metadata.CredentialMetadata;
import io.fabric8.kubernetes.client.ResourceNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class CredentialMetadataService {
    private final CredentialMetadata credentialMetadata;

    public String getCredentialTypeMetadata(String metadataKey) {
        return getMapValue(credentialMetadata.getVctMetadataMap(), metadataKey);
    }

    public String getJsonSchema(String jsonSchemaKey) {
        return getMapValue(credentialMetadata.getJsonSchemaMap(), jsonSchemaKey);
    }

    public String getOverlaysCaptureArchitecture(String overlaysCaptureArchitectureKey) {
        return getMapValue(credentialMetadata.getOverlayCaptureArchitectureMap(), overlaysCaptureArchitectureKey);
    }

    private String getMapValue(Map<String, String> metadataMap, String key) {
        if (metadataMap != null && metadataMap.containsKey(key)) {
            return metadataMap.get(key);
        }
        throw new ResourceNotFoundException(key);
    }
}
