package ch.admin.bj.swiyu.issuer.infrastructure.config;

import ch.admin.bj.swiyu.issuer.common.config.HttpConfig;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
@AllArgsConstructor
public class RestClientConfiguration {
    private final HttpConfig httpConfig;

    @Bean
    public WebClient defaultWebClient(WebClient.Builder builder) {
        return builder
                .codecs(configurer -> configurer
                        .defaultCodecs()
                        .maxInMemorySize(httpConfig.getObjectSizeLimit()))
                .build();
    }
}