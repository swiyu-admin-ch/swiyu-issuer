package ch.admin.bj.swiyu.issuer.infrastructure.config;

import ch.admin.bj.swiyu.issuer.domain.openid.metadata.*;
import ch.admin.bj.swiyu.issuer.dto.callback.WebhookCallbackDto;
import ch.admin.bj.swiyu.issuer.dto.exception.ApiErrorDto;
import io.swagger.v3.core.converter.ModelConverters;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import org.springdoc.core.customizers.GlobalOpenApiCustomizer;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.LinkedHashMap;
import java.util.TreeMap;

/**
 * Configures the OpenAPI document used by Springdoc for the issuer service.
 */
@Configuration
@SecurityScheme(
        name = "bearer-jwt",
        type = SecuritySchemeType.HTTP,
        scheme = "bearer",
        bearerFormat = "JWT"
)
public class OpenApiConfig {

    /**
     * Creates the base OpenAPI metadata for the generated specification.
     *
     * @return the OpenAPI definition with the service title and description
     */
    @Bean
    public OpenAPI openApi() {
        return new OpenAPI().info(new io.swagger.v3.oas.models.info.Info()
                .title("Issuer Service API")
                .description("Generic swiyu Issuer Service service")
        );
    }

    @Bean
    GroupedOpenApi api() {
        return GroupedOpenApi.builder()
                .group("API")
                .pathsToMatch("/**")
                .build();
    }

    /**
     * Adds custom schemas to the generated OpenAPI document in a stable order.
     *
     * @return a customizer that injects the shared schemas into the components section
     */
    @Bean
    public GlobalOpenApiCustomizer openApiCustomizer() {
        var additionalSchemas = new LinkedHashMap<String, io.swagger.v3.oas.models.media.Schema<?>>();
        additionalSchemas.put("ApiError", ModelConverters.getInstance().readAllAsResolvedSchema(ApiErrorDto.class).schema);
        additionalSchemas.put("WebhookCallback", ModelConverters.getInstance().readAllAsResolvedSchema(WebhookCallbackDto.class).schema);
        additionalSchemas.put("IssuerMetadata", ModelConverters.getInstance().readAllAsResolvedSchema(IssuerMetadata.class).schema);
        additionalSchemas.put("CredentialConfiguration", ModelConverters.getInstance().readAllAsResolvedSchema(CredentialConfiguration.class).schema);
        additionalSchemas.put("IssuerCredentialRequestEncryption", ModelConverters.getInstance().readAllAsResolvedSchema(IssuerCredentialRequestEncryption.class).schema);
        additionalSchemas.put("IssuerCredentialResponseEncryption", ModelConverters.getInstance().readAllAsResolvedSchema(IssuerCredentialResponseEncryption.class).schema);
        additionalSchemas.put("BatchCredentialIssuance", ModelConverters.getInstance().readAllAsResolvedSchema(BatchCredentialIssuance.class).schema);
        additionalSchemas.put("MetadataIssuerDisplayInfo", ModelConverters.getInstance().readAllAsResolvedSchema(MetadataIssuerDisplayInfo.class).schema);
        additionalSchemas.put("MetadataLogo", ModelConverters.getInstance().readAllAsResolvedSchema(MetadataLogo.class).schema);
        additionalSchemas.put("CredentialDefinition", ModelConverters.getInstance().readAllAsResolvedSchema(CredentialDefinition.class).schema);
        additionalSchemas.put("SupportedProofType", ModelConverters.getInstance().readAllAsResolvedSchema(SupportedProofType.class).schema);
        additionalSchemas.put("MetadataCredentialDisplayInfo", ModelConverters.getInstance().readAllAsResolvedSchema(MetadataCredentialDisplayInfo.class).schema);
        additionalSchemas.put("CredentialConfigurationMetadata", ModelConverters.getInstance().readAllAsResolvedSchema(CredentialConfigurationMetadata.class).schema);
        additionalSchemas.put("MetadataClaimDescriptor", ModelConverters.getInstance().readAllAsResolvedSchema(MetadataClaimDescriptor.class).schema);
        additionalSchemas.put("MetadataImage", ModelConverters.getInstance().readAllAsResolvedSchema(MetadataImage.class).schema);
        additionalSchemas.put("KeyAttestationRequirement", ModelConverters.getInstance().readAllAsResolvedSchema(KeyAttestationRequirement.class).schema);
        additionalSchemas.put("MetadataDisplayInfo", ModelConverters.getInstance().readAllAsResolvedSchema(MetadataDisplayInfo.class).schema);
        return openApi -> {
            if (openApi.getComponents() == null) {
                openApi.setComponents(new Components());
            }
            var orderedSchemas = new TreeMap<String, io.swagger.v3.oas.models.media.Schema<?>>();
            if (openApi.getComponents().getSchemas() != null) {
                openApi.getComponents().getSchemas().forEach((schemaName, schema) ->
                        orderedSchemas.put(schemaName, (io.swagger.v3.oas.models.media.Schema<?>) schema));
            }
            orderedSchemas.putAll(additionalSchemas);
            orderedSchemas.forEach((name, schema) -> {
                if (schema.getTypes() == null && schema.getProperties() != null && !schema.getProperties().isEmpty()) {
                    schema.addType("object");
                }
            });
            openApi.getComponents().setSchemas(new LinkedHashMap<>(orderedSchemas));
        };
    }
}