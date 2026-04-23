package ch.admin.bj.swiyu.issuer.pact.consumer;

import ch.admin.bit.jeap.security.test.client.MockJeapOAuth2RestClientBuilderFactory;
import ch.admin.bit.jeap.security.test.jws.JwsBuilderFactory;
import ch.admin.bit.jeap.security.test.jws.TestKeyProvider;
import ch.admin.bit.jeap.security.test.jws.TestKeyProviderConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ResourceLoader;
import org.springframework.web.client.RestClient;

@TestConfiguration
@EnableConfigurationProperties(TestKeyProviderConfigurationProperties.class)
public class PactConsumerTestConfig {

    @Bean
    public RestClient.Builder provideRestClientBuilder() {
        return RestClient.builder();
    }

    @Bean
    public MockJeapOAuth2RestClientBuilderFactory mockRestClientBuilderFactory(RestClient.Builder builder) {
        return new MockJeapOAuth2RestClientBuilderFactory(builder);
    }

    @Bean
    public TestKeyProvider testKeyProvider(
            TestKeyProviderConfigurationProperties props,
            ResourceLoader resourceLoader
    ) {
        return new TestKeyProvider(props, resourceLoader);
    }

    @Bean
    public JwsBuilderFactory jwsBuilderFactory(TestKeyProvider testKeyProvider) {
        return new JwsBuilderFactory(testKeyProvider);
    }
}