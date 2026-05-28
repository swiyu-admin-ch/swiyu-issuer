package ch.admin.bj.swiyu.issuer.infrastructure.config;

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
        return openApi -> {
            if (openApi.getComponents() == null) {
                openApi.setComponents(new Components());
            }
            if (openApi.getComponents().getSchemas() == null) {
                openApi.getComponents().setSchemas(new LinkedHashMap<>());
            }
            openApi.getComponents().getSchemas().putAll(additionalSchemas);
        };
    }
}