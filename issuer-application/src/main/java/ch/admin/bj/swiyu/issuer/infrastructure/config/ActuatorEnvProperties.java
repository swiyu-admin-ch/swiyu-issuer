package ch.admin.bj.swiyu.issuer.infrastructure.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@Getter
@Setter
@ConfigurationProperties("management.endpoint.env")
public class ActuatorEnvProperties {
    private List<String> allowedProperties = List.of();
}

