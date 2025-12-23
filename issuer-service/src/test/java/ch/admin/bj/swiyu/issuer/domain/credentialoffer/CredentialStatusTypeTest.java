package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CredentialStatusTypeTest {

    @Test
    void testGetExpirableStates() {
        List<CredentialOfferStatusType> status = CredentialOfferStatusType.getExpirableStates();
        assertTrue(status.contains(CredentialOfferStatusType.OFFERED));
        assertTrue(status.contains(CredentialOfferStatusType.IN_PROGRESS));
        assertTrue(status.contains(CredentialOfferStatusType.DEFERRED));
        assertTrue(status.contains(CredentialOfferStatusType.READY));
        assertTrue(status.contains(CredentialOfferStatusType.REQUESTED));
        assertEquals(5, status.size());
    }

    @Test
    void testIsProcessable() {
        assertTrue(CredentialOfferStatusType.OFFERED.isProcessable());
        assertTrue(CredentialOfferStatusType.IN_PROGRESS.isProcessable());
        assertTrue(CredentialOfferStatusType.DEFERRED.isProcessable());
        assertTrue(CredentialOfferStatusType.READY.isProcessable());
        assertFalse(CredentialOfferStatusType.ISSUED.isProcessable());
        assertFalse(CredentialOfferStatusType.EXPIRED.isProcessable());
        assertFalse(CredentialOfferStatusType.CANCELLED.isProcessable());
    }

    @Test
    void testIsTerminalState() {
        assertTrue(CredentialOfferStatusType.EXPIRED.isTerminalState());
        assertTrue(CredentialOfferStatusType.CANCELLED.isTerminalState());
        assertTrue(CredentialOfferStatusType.ISSUED.isTerminalState());
        assertFalse(CredentialOfferStatusType.OFFERED.isTerminalState());
        assertFalse(CredentialOfferStatusType.IN_PROGRESS.isTerminalState());
        assertFalse(CredentialOfferStatusType.DEFERRED.isTerminalState());
        assertFalse(CredentialOfferStatusType.READY.isTerminalState());
    }
}