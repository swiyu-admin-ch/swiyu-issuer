package ch.admin.bj.swiyu.issuer.service;

import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusType;
import ch.admin.bj.swiyu.issuer.service.persistence.CredentialPersistenceService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CredentialOfferExpirationServiceTest {

    private static final long PAST = Instant.now().minusSeconds(300).getEpochSecond();
    private static final long FUTURE = Instant.now().plusSeconds(300).getEpochSecond();

    @Mock
    private CredentialPersistenceService persistenceService;

    @Mock
    private CredentialStateService stateService;

    private CredentialOfferExpirationService expirationService;

    private AutoCloseable mocks;

    @BeforeEach
    void setUp() {
        mocks = MockitoAnnotations.openMocks(this);
        expirationService = new CredentialOfferExpirationService(persistenceService, stateService);
    }

    @AfterEach
    void tearDown() throws Exception {
        if (mocks != null) {
            mocks.close();
        }
    }

    /**
     * Happy path: an offer in an expirable state whose expiration timestamp has passed is expired.
     */
    @Test
    void expireOffer_shouldExpireExpiredOffer() {
        var offerId = UUID.randomUUID();
        var offer = offer(offerId, CredentialOfferStatusType.OFFERED, PAST);
        when(persistenceService.findCredentialOfferByIdForUpdate(offerId)).thenReturn(offer);

        var expired = expirationService.expireOffer(offerId);

        assertTrue(expired);
        verify(stateService, times(1)).expireOfferAndPublish(offer);
    }

    /**
     * An offer which already reached a terminal state (e.g. issued) must not be expired again.
     */
    @Test
    void expireOffer_shouldSkipOfferInNonExpirableState() {
        var offerId = UUID.randomUUID();
        var offer = offer(offerId, CredentialOfferStatusType.ISSUED, PAST);
        when(persistenceService.findCredentialOfferByIdForUpdate(offerId)).thenReturn(offer);

        var expired = expirationService.expireOffer(offerId);

        assertFalse(expired);
        verify(stateService, never()).expireOfferAndPublish(any());
    }

    /**
     * An offer whose expiration timestamp was extended (e.g. by the deferred flow) must not be expired.
     */
    @Test
    void expireOffer_shouldSkipOfferWithoutPassedExpirationTimestamp() {
        var offerId = UUID.randomUUID();
        var offer = offer(offerId, CredentialOfferStatusType.OFFERED, FUTURE);
        when(persistenceService.findCredentialOfferByIdForUpdate(offerId)).thenReturn(offer);

        var expired = expirationService.expireOffer(offerId);

        assertFalse(expired);
        verify(stateService, never()).expireOfferAndPublish(any());
    }

    private CredentialOffer offer(UUID offerId, CredentialOfferStatusType status, long expirationEpoch) {
        return CredentialOffer.builder()
                .id(offerId)
                .credentialStatus(status)
                .offerExpirationTimestamp(expirationEpoch)
                .build();
    }
}
