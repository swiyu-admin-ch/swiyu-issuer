package ch.admin.bj.swiyu.issuer.management.infrastructure.web.config;

import io.swagger.v3.oas.models.OpenAPI;
import lombok.AllArgsConstructor;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.boot.info.BuildProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@AllArgsConstructor
@Configuration
public class OpenApiConfig {
    private final BuildProperties buildProperties;

    @Bean
    public OpenAPI openApi() {
        return new OpenAPI().info(new io.swagger.v3.oas.models.info.Info()
                .title("Issuer management API")
                .description("Generic Issuer management service")
                .version(buildProperties.getVersion())
                .contact(new io.swagger.v3.oas.models.info.Contact()
                        .name("e-ID - Team Tergum")
                        .email("eid@bit.admin.ch")
                )
        );

    }

    @Bean
    GroupedOpenApi api() {
        return GroupedOpenApi.builder()
                .group("API")
                .pathsToMatch("/**")
                .packagesToScan("ch.admin.bj.swiyu.issuer.management")
                .build();
    }
}
