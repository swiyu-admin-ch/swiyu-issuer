package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CredentialStatusTypeTest {

    @Test
    void testDisplayNameAndToString() {
        assertEquals("Offered", CredentialOfferStatusType.OFFERED.getDisplayName());
        assertEquals("Offered", CredentialOfferStatusType.OFFERED.toString());
        assertEquals("Claiming in Progress", CredentialOfferStatusType.IN_PROGRESS.toString());
        assertEquals("Deferred", CredentialOfferStatusType.DEFERRED.toString());
        assertEquals("Ready", CredentialOfferStatusType.READY.toString());
        assertEquals("Issued", CredentialOfferStatusType.ISSUED.toString());
        assertEquals("Suspended", CredentialOfferStatusType.SUSPENDED.toString());
        assertEquals("Revoked", CredentialOfferStatusType.REVOKED.toString());
        assertEquals("Expired", CredentialOfferStatusType.EXPIRED.toString());
        assertEquals("Cancelled", CredentialOfferStatusType.CANCELLED.toString());
    }

    @Test
    void testGetExpirableStates() {
        List<CredentialOfferStatusType> status = CredentialOfferStatusType.getExpirableStates();
        assertTrue(status.contains(CredentialOfferStatusType.OFFERED));
        assertTrue(status.contains(CredentialOfferStatusType.IN_PROGRESS));
        assertTrue(status.contains(CredentialOfferStatusType.DEFERRED));
        assertTrue(status.contains(CredentialOfferStatusType.READY));
        assertEquals(4, status.size());
    }

    @Test
    void testIsProcessable() {
        assertTrue(CredentialOfferStatusType.OFFERED.isProcessable());
        assertTrue(CredentialOfferStatusType.IN_PROGRESS.isProcessable());
        assertTrue(CredentialOfferStatusType.DEFERRED.isProcessable());
        assertTrue(CredentialOfferStatusType.READY.isProcessable());
        assertFalse(CredentialOfferStatusType.ISSUED.isProcessable());
        assertFalse(CredentialOfferStatusType.SUSPENDED.isProcessable());
        assertFalse(CredentialOfferStatusType.REVOKED.isProcessable());
        assertFalse(CredentialOfferStatusType.EXPIRED.isProcessable());
        assertFalse(CredentialOfferStatusType.CANCELLED.isProcessable());
    }

    @Test
    void testIsTerminalState() {
        assertTrue(CredentialOfferStatusType.REVOKED.isTerminalState());
        assertTrue(CredentialOfferStatusType.EXPIRED.isTerminalState());
        assertTrue(CredentialOfferStatusType.CANCELLED.isTerminalState());
        assertFalse(CredentialOfferStatusType.OFFERED.isTerminalState());
        assertFalse(CredentialOfferStatusType.IN_PROGRESS.isTerminalState());
        assertFalse(CredentialOfferStatusType.DEFERRED.isTerminalState());
        assertFalse(CredentialOfferStatusType.READY.isTerminalState());
        assertFalse(CredentialOfferStatusType.ISSUED.isTerminalState());
        assertFalse(CredentialOfferStatusType.SUSPENDED.isTerminalState());
    }
}