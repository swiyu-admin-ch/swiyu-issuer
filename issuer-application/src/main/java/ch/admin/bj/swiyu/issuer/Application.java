package ch.admin.bj.swiyu.issuer;

import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.EnableSchedulerLock;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.autoconfigure.endpoint.jmx.JmxEndpointAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.admin.SpringApplicationAdminJmxAutoConfiguration;
import org.springframework.boot.autoconfigure.jmx.JmxAutoConfiguration;
import org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.core.env.Environment;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Attack-surface reduction via compile-safe {@code exclude} references.
 */
@SpringBootApplication(
        exclude = {
                // Disables the default in-memory user store; authentication is delegated to Keycloak.
                UserDetailsServiceAutoConfiguration.class,

                // JMX: common source of CVEs and unused in containerised deployments.
                // All three JMX-related auto-configurations must be excluded together:
                //   JmxAutoConfiguration             – sets up the MBeanServer infrastructure
                //   SpringApplicationAdminJmxAutoConfiguration – exports app admin data over JMX
                //   JmxEndpointAutoConfiguration     – exposes Actuator endpoints over JMX
                JmxAutoConfiguration.class,
                SpringApplicationAdminJmxAutoConfiguration.class,
                JmxEndpointAutoConfiguration.class
        }
)
@EnableConfigurationProperties
@ConfigurationPropertiesScan
@EnableScheduling
@EnableSchedulerLock(defaultLockAtMostFor = "10m")
@EnableAsync
@Slf4j
public class Application {

    public static void main(String[] args) {
        Environment env = SpringApplication.run(Application.class, args).getEnvironment();
        String appName = env.getProperty("spring.application.name");
        String serverPort = env.getProperty("server.port");
        log.info(
                """
                        
                        ----------------------------------------------------------------------------
                        \t'{}' is running!\s
                        \tProfile(s): \t\t\t\t{}
                        \tSwaggerUI:   \t\t\t\thttp://localhost:{}/swagger-ui.html
                        ----------------------------------------------------------------------------""",
                appName,
                env.getActiveProfiles(),
                serverPort
        );
    }
}