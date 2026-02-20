package ch.admin.bj.swiyu.issuer.dto.type_metadata;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

import java.util.List;

public record TypeMetadataDto(

        @NotNull(message = "'profile_version' must be set")
        @JsonProperty("profile_version")
        @Pattern(regexp = "^swiss-profile-vc:1.0.0$", message = "Profile version must be 'swiss-profile-vc:1.0.0'")
        String profileVersion,

        String vct,

        // A human-readable name for the type, intended for developers reading the JSON document. This property is OPTIONAL.
        String name,

        // A human-readable description for the type, intended for developers reading the JSON document. This property is OPTIONAL.
        String description,

        // A URI of another type that this type extends, as described in Section 8. This property is OPTIONAL.
        @JsonProperty("extends")
        String extendsType,

        // An object containing claim information for the type, as described in Section 9. This property is OPTIONAL.
        Object claims,

        //  An embedded JSON Schema document describing the structure of the Verifiable Credential as described in Section 6.5.1. schema MUST NOT be used if schema_uri is present.
        Object schema,

        //  A URL pointing to a JSON Schema document describing the structure of the Verifiable Credential as described in Section 6.5.1. schema_uri MUST NOT be used if schema is present.
        @JsonProperty("schema_uri")
        String schemaUri,

        // An embedded JSON Schema document describing the structure of the Verifiable Credential as described in Section 6.5.1. schema MUST NOT be used if schema_uri is present.
        @JsonProperty("schema_uri#integrity")
        String schemaUriIntegrity,

        // An object containing display information for the type, as described in Section 8. This property is OPTIONAL.
        @Valid
        List<TypeMetadataDisplayDto> display
) {
}