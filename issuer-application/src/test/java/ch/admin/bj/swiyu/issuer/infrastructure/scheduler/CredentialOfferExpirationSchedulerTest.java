package ch.admin.bj.swiyu.issuer.infrastructure.scheduler;

import ch.admin.bj.swiyu.issuer.service.CredentialOfferExpirationService;
import ch.admin.bj.swiyu.issuer.service.persistence.CredentialPersistenceService;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link CredentialOfferExpirationScheduler}.
 *
 * <p>Focuses on the resilience of the scheduled job: an offer whose persisted data can not be processed must be
 * logged and skipped without preventing the expiration of the remaining offers.</p>
 */
class CredentialOfferExpirationSchedulerTest {

    @Mock
    private CredentialPersistenceService persistenceService;

    @Mock
    private CredentialOfferExpirationService credentialOfferExpirationService;

    private CredentialOfferExpirationScheduler scheduler;

    private AutoCloseable mocks;

    private Logger schedulerLogger;

    private ListAppender<ILoggingEvent> logAppender;

    @BeforeEach
    void setUp() {
        mocks = MockitoAnnotations.openMocks(this);
        scheduler = new CredentialOfferExpirationScheduler(persistenceService, credentialOfferExpirationService);

        // Capture the logs of the scheduler to assert that broken offers are reported
        schedulerLogger = (Logger) LoggerFactory.getLogger(CredentialOfferExpirationScheduler.class);
        logAppender = new ListAppender<>();
        logAppender.start();
        schedulerLogger.addAppender(logAppender);
    }

    @AfterEach
    void tearDown() throws Exception {
        schedulerLogger.detachAppender(logAppender);
        logAppender.stop();
        if (mocks != null) {
            mocks.close();
        }
    }

    /**
     * Happy path: every offer reported as expired is handed to the expiration service.
     */
    @Test
    void expireOffers_shouldExpireAllExpiredOffers() {
        var offerIds = List.of(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID());
        when(persistenceService.findExpiredOfferIds(anyList(), anyLong())).thenReturn(offerIds);

        scheduler.expireOffers();

        offerIds.forEach(offerId -> verify(credentialOfferExpirationService, times(1)).expireOffer(offerId));
    }

    /**
     * A single offer whose persisted data can no longer be processed must not abort the job: the failure is logged
     * together with the affected offer ID and all remaining offers are still expired.
     */
    @Test
    void expireOffers_shouldLogAndSkipOfferWhichCannotBeExpired() {
        var brokenOfferId = UUID.randomUUID();
        var otherOfferId = UUID.randomUUID();
        var offerAfterBrokenOfferId = UUID.randomUUID();
        when(persistenceService.findExpiredOfferIds(
                anyList(), anyLong()))
                .thenReturn(List.of(brokenOfferId, otherOfferId, offerAfterBrokenOfferId));
        doThrow(new IllegalStateException("persisted offer data can not be read"))
                .when(credentialOfferExpirationService).expireOffer(brokenOfferId);

        scheduler.expireOffers();

        // The offers after the broken one are processed as well
        verify(credentialOfferExpirationService, times(1)).expireOffer(otherOfferId);
        verify(credentialOfferExpirationService, times(1)).expireOffer(offerAfterBrokenOfferId);

        var errorEvents = logAppender.list.stream()
                .filter(event -> event.getLevel() == Level.ERROR)
                .toList();
        assertThat(errorEvents)
                .hasSize(1)
                .allSatisfy(event -> {
                    assertThat(event.getFormattedMessage()).contains(brokenOfferId.toString());
                    assertThat(event.getThrowableProxy()).isNotNull();
                });

        var warnEvents = logAppender.list.stream()
                .filter(event -> event.getLevel() == Level.WARN)
                .toList();
        assertThat(warnEvents)
                .singleElement()
                .satisfies(event -> assertThat(event.getFormattedMessage())
                        .contains("1 of 3")
                        .contains(brokenOfferId.toString()));
    }

    /**
     * Without any expired offer nothing is expired and no warning is logged.
     */
    @Test
    void expireOffers_shouldDoNothingWhenNoOfferIsExpired() {
        when(persistenceService.findExpiredOfferIds(anyList(), anyLong())).thenReturn(List.of());

        scheduler.expireOffers();

        verifyNoInteractions(credentialOfferExpirationService);
        assertThat(logAppender.list)
                .noneMatch(event -> event.getLevel() == Level.WARN || event.getLevel() == Level.ERROR);
    }
}