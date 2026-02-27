package ch.admin.bj.swiyu.issuer.common.config;

import org.mockito.Mockito;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

import ch.admin.bj.swiyu.issuer.service.persistence.CredentialPersistenceService;
import ch.admin.bj.swiyu.issuer.service.statuslist.StatusListPersistenceService;
import ch.admin.bj.swiyu.issuer.service.webhook.EventProducerService;

@TestConfiguration
class StateMachineMockConfig {
    @Bean
    CredentialPersistenceService mockCredentialPersistenceService() {
        return Mockito.mock(CredentialPersistenceService.class);
    }
    @Bean
    StatusListPersistenceService mockStatusListPersistenceService() {
        return Mockito.mock(StatusListPersistenceService.class);
    }
    @Bean
    EventProducerService mockEventProducerService() {
        return Mockito.mock(EventProducerService.class);
    }
}
