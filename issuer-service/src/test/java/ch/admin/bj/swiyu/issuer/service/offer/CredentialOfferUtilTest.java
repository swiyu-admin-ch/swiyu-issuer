package ch.admin.bj.swiyu.issuer.service.offer;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOffer;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferRepository;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusType;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStateMachine;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.statemachine.CredentialStateMachineConfig.CredentialOfferEvent;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;

class CredentialOfferUtilTest {

    private CredentialStateMachine credenitalStateMachine;
    private CredentialOfferRepository credentialOfferRepository;

    @BeforeEach
    void setup() {
        credenitalStateMachine = mock(CredentialStateMachine.class);
        credentialOfferRepository = mock(CredentialOfferRepository.class);
    }

    @ParameterizedTest
    @CsvSource({
        "CANCELLED,true,0", "EXPIRED,true,0", "ISSUED,true,0",
        "CANCELLED,false,0", "EXPIRED,false,0", "ISSUED,false,0",
        "INIT,false,0", "OFFERED,false,0", "IN_PROGRESS,false,0", "DEFERRED,false,0", "REQUESTED,false,0",
        "INIT,true,1", "OFFERED,true,1", "IN_PROGRESS,true,1", "DEFERRED,true,1", "REQUESTED,true,1"
    })
    void getExpirationCheckedCredentialOffer_whenState(String stringState, boolean expired, int numberOfExpectedUpdates) {
        var state = CredentialOfferStatusType.valueOf(stringState);
        CredentialOffer offer = mock(CredentialOffer.class);
        when(offer.getCredentialStatus()).thenReturn(state);
        when(offer.isTerminatedOffer()).thenCallRealMethod();
        when(offer.hasExpirationTimeStampPassed()).thenReturn(expired);
        CredentialOfferUtil.getExpirationCheckedCredentialOffer(offer, credenitalStateMachine, credentialOfferRepository);
        verify(credenitalStateMachine, times(numberOfExpectedUpdates)).sendEventAndUpdateStatus(same(offer), eq(CredentialOfferEvent.EXPIRE));
        verify(credentialOfferRepository, times(numberOfExpectedUpdates)).save(same(offer));
    }
}
