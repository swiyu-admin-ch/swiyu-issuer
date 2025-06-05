package ch.admin.bj.swiyu.issuer.infrastructure.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties("webhook")
public class WebhookProperties {
    private String callbackUri;
    private String apiKey;
}
