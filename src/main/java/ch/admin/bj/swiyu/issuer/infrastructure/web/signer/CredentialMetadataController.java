package ch.admin.bj.swiyu.issuer.infrastructure.web.signer;

import ch.admin.bj.swiyu.issuer.service.CredentialMetadataService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AllArgsConstructor
@Slf4j
@Tag(name = "Credential Metadata", description = "Metadata for Verifiable Credentials")
public class CredentialMetadataController {

    private CredentialMetadataService credentialMetadataService;

    @GetMapping(path = "vct/{metadataKey}", produces = {MediaType.APPLICATION_JSON_VALUE})
    public String getCredentialTypeMetadata(@PathVariable String metadataKey) {
        return credentialMetadataService.getCredentialTypeMetadata(metadataKey);
    }

    @GetMapping(path = "json-schema/{schemaKey}", produces = {"application/schema+json"})
    public String getJsonSchema(@PathVariable String schemaKey) {
        return credentialMetadataService.getJsonSchema(schemaKey);
    }

    @GetMapping(path = "oca/{ocaKey}", produces = {MediaType.APPLICATION_JSON_VALUE})
    public String getOverlaysCaptureArchitecture(@PathVariable String ocaKey) {
        return credentialMetadataService.getOverlaysCaptureArchitecture(ocaKey);
    }

}
