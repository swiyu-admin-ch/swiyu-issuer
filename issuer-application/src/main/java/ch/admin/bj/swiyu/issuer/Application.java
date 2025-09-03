/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer;

import lombok.extern.slf4j.Slf4j;
import net.javacrumbs.shedlock.spring.annotation.EnableSchedulerLock;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.core.env.Environment;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication(exclude = {UserDetailsServiceAutoConfiguration.class})
@EnableConfigurationProperties
@ConfigurationPropertiesScan
@EnableScheduling
@EnableAsync
@EnableSchedulerLock(defaultLockAtMostFor = "10m")
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