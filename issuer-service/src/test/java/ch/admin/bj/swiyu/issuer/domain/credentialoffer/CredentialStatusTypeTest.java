package ch.admin.bj.swiyu.issuer.domain.credentialoffer;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CredentialStatusTypeTest {

    @Test
    void testDisplayNameAndToString() {
        assertEquals("Offered", CredentialStatusType.OFFERED.getDisplayName());
        assertEquals("Offered", CredentialStatusType.OFFERED.toString());
        assertEquals("Claiming in Progress", CredentialStatusType.IN_PROGRESS.toString());
        assertEquals("Deferred", CredentialStatusType.DEFERRED.toString());
        assertEquals("Ready", CredentialStatusType.READY.toString());
        assertEquals("Issued", CredentialStatusType.ISSUED.toString());
        assertEquals("Suspended", CredentialStatusType.SUSPENDED.toString());
        assertEquals("Revoked", CredentialStatusType.REVOKED.toString());
        assertEquals("Expired", CredentialStatusType.EXPIRED.toString());
        assertEquals("Cancelled", CredentialStatusType.CANCELLED.toString());
    }

    @Test
    void testGetExpirableStates() {
        List<CredentialStatusType> status = CredentialStatusType.getExpirableStates();
        assertTrue(status.contains(CredentialStatusType.OFFERED));
        assertTrue(status.contains(CredentialStatusType.IN_PROGRESS));
        assertTrue(status.contains(CredentialStatusType.DEFERRED));
        assertTrue(status.contains(CredentialStatusType.READY));
        assertEquals(4, status.size());
    }

    @Test
    void testIsProcessable() {
        assertTrue(CredentialStatusType.OFFERED.isProcessable());
        assertTrue(CredentialStatusType.IN_PROGRESS.isProcessable());
        assertTrue(CredentialStatusType.DEFERRED.isProcessable());
        assertTrue(CredentialStatusType.READY.isProcessable());
        assertFalse(CredentialStatusType.ISSUED.isProcessable());
        assertFalse(CredentialStatusType.SUSPENDED.isProcessable());
        assertFalse(CredentialStatusType.REVOKED.isProcessable());
        assertFalse(CredentialStatusType.EXPIRED.isProcessable());
        assertFalse(CredentialStatusType.CANCELLED.isProcessable());
    }

    @Test
    void testIsTerminalState() {
        assertTrue(CredentialStatusType.REVOKED.isTerminalState());
        assertTrue(CredentialStatusType.EXPIRED.isTerminalState());
        assertTrue(CredentialStatusType.CANCELLED.isTerminalState());
        assertFalse(CredentialStatusType.OFFERED.isTerminalState());
        assertFalse(CredentialStatusType.IN_PROGRESS.isTerminalState());
        assertFalse(CredentialStatusType.DEFERRED.isTerminalState());
        assertFalse(CredentialStatusType.READY.isTerminalState());
        assertFalse(CredentialStatusType.ISSUED.isTerminalState());
        assertFalse(CredentialStatusType.SUSPENDED.isTerminalState());
    }
}