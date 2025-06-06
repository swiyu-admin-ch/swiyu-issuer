package ch.admin.bj.swiyu.issuer.infrastructure.config;

import ch.admin.bj.swiyu.issuer.common.config.HttpConfig;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;

@Configuration
@AllArgsConstructor
public class RestClientConfiguration {
    private final HttpConfig httpConfig;

    @Bean
    public RestClient defaultRestClient(RestClient.Builder builder) {
        return builder
                .requestInterceptor(new ContentLengthInterceptor(httpConfig.getObjectSizeLimit()))
                .build();
    }
}