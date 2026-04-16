package ch.admin.bj.swiyu.issuer.infrastructure.health;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

import java.lang.annotation.*;

@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@ConditionalOnProperty(prefix = "management.endpoint.health", name = "registry-health-checks-enabled", havingValue = "true")
public @interface ConditionalRegistryHealthChecksEnabled {
}