package ch.admin.bj.swiyu.issuer.service.statuslist;

import ch.admin.bj.swiyu.issuer.api.credentialoffer.CreateCredentialOfferRequestDto;
import ch.admin.bj.swiyu.issuer.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatus;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatusKey;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusManagementType;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusList;
import ch.admin.bj.swiyu.issuer.service.StatusListService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class StatusListManagementServiceTest {

    @Mock
    private StatusListService statusListService;

    private StatusListManagementService statusListManagementService;

    private AutoCloseable mocks;

    @BeforeEach
    void setUp() {
        mocks = MockitoAnnotations.openMocks(this);
        statusListManagementService = new StatusListManagementService(statusListService);
    }

    @AfterEach
    void tearDown() throws Exception {
        if (mocks != null) {
            mocks.close();
        }
    }

    /**
     * Happy path: all requested status list URIs can be resolved and are returned.
     */
    @Test
    void resolveAndValidateStatusLists_shouldReturnListsWhenAllResolved() {
        var uri1 = "https://example.com/status1";
        var uri2 = "https://example.com/status2";
        var statusList1 = StatusList.builder().uri(uri1).build();
        var statusList2 = StatusList.builder().uri(uri2).build();

        var request = CreateCredentialOfferRequestDto.builder()
                .statusLists(List.of(uri1, uri2))
                .build();

        when(statusListService.findByUriIn(List.of(uri1, uri2)))
                .thenReturn(List.of(statusList1, statusList2));

        var result = statusListManagementService.resolveAndValidateStatusLists(request);

        assertEquals(List.of(statusList1, statusList2), result);
        verify(statusListService).findByUriIn(List.of(uri1, uri2));
        verifyNoMoreInteractions(statusListService);
    }

    /**
     * Exception path: if not all provided URIs can be resolved, the method must fail and include
     * the resolved URIs in the error message.
     */
    @Test
    void resolveAndValidateStatusLists_shouldThrowWhenNotAllResolved() {
        var uri1 = "https://example.com/status1";
        var uri2 = "https://example.com/status2";
        var statusList1 = StatusList.builder().uri(uri1).build();

        var request = CreateCredentialOfferRequestDto.builder()
                .statusLists(List.of(uri1, uri2))
                .build();

        when(statusListService.findByUriIn(List.of(uri1, uri2)))
                .thenReturn(List.of(statusList1)); // Only one resolved

        var ex = assertThrows(BadRequestException.class,
                () -> statusListManagementService.resolveAndValidateStatusLists(request));

        assertTrue(ex.getMessage().contains(uri1));
        assertFalse(ex.getMessage().contains(uri2));
    }

    /**
     * Edge case: an empty list of status lists should be considered valid and results in an empty resolution.
     */
    @Test
    void resolveAndValidateStatusLists_shouldReturnEmptyWhenRequestIsEmpty() {
        var request = CreateCredentialOfferRequestDto.builder()
                .statusLists(List.of())
                .build();

        when(statusListService.findByUriIn(List.of())).thenReturn(List.of());

        var result = statusListManagementService.resolveAndValidateStatusLists(request);

        assertNotNull(result);
        assertTrue(result.isEmpty());
        verify(statusListService).findByUriIn(List.of());
        verifyNoMoreInteractions(statusListService);
    }

    /**
     * Happy path: updating to {@link CredentialStatusManagementType#REVOKED} delegates to
     * {@link StatusListService#revoke(Set)} and returns the affected status list IDs.
     */
    @Test
    void updateStatusListsForPostIssuance_shouldRevokeWhenStatusIsRevoked() {
        var offerStatusSet = Set.of(CredentialOfferStatus.builder()
                .id(CredentialOfferStatusKey.builder()
                        .offerId(UUID.randomUUID())
                        .statusListId(UUID.randomUUID())
                        .index(1)
                        .build())
                .build());

        var expectedIds = List.of(UUID.randomUUID(), UUID.randomUUID());
        when(statusListService.revoke(offerStatusSet)).thenReturn(expectedIds);

        var result = statusListManagementService.updateStatusListsForPostIssuance(
                offerStatusSet, CredentialStatusManagementType.REVOKED);

        assertEquals(expectedIds, result);
        verify(statusListService, times(1)).revoke(offerStatusSet);
        verifyNoMoreInteractions(statusListService);
    }

    /**
     * Happy path: updating to {@link CredentialStatusManagementType#SUSPENDED} delegates to
     * {@link StatusListService#suspend(Set)}.
     */
    @Test
    void updateStatusListsForPostIssuance_shouldSuspendWhenStatusIsSuspended() {
        var offerStatusSet = Set.of(CredentialOfferStatus.builder()
                .id(CredentialOfferStatusKey.builder()
                        .offerId(UUID.randomUUID())
                        .statusListId(UUID.randomUUID())
                        .index(1)
                        .build())
                .build());

        var expectedIds = List.of(UUID.randomUUID());
        when(statusListService.suspend(offerStatusSet)).thenReturn(expectedIds);

        var result = statusListManagementService.updateStatusListsForPostIssuance(
                offerStatusSet, CredentialStatusManagementType.SUSPENDED);

        assertEquals(expectedIds, result);
        verify(statusListService, times(1)).suspend(offerStatusSet);
        verifyNoMoreInteractions(statusListService);
    }

    /**
     * Happy path: updating to {@link CredentialStatusManagementType#ISSUED} delegates to
     * {@link StatusListService#revalidate(Set)} (re-validating a previously revoked/suspended credential).
     */
    @Test
    void updateStatusListsForPostIssuance_shouldRevalidateWhenStatusIsIssued() {
        var offerStatusSet = Set.of(CredentialOfferStatus.builder()
                .id(CredentialOfferStatusKey.builder()
                        .offerId(UUID.randomUUID())
                        .statusListId(UUID.randomUUID())
                        .index(1)
                        .build())
                .build());

        var expectedIds = List.of(UUID.randomUUID());
        when(statusListService.revalidate(offerStatusSet)).thenReturn(expectedIds);

        var result = statusListManagementService.updateStatusListsForPostIssuance(
                offerStatusSet, CredentialStatusManagementType.ISSUED);

        assertEquals(expectedIds, result);
        verify(statusListService, times(1)).revalidate(offerStatusSet);
        verifyNoMoreInteractions(statusListService);
    }

    /**
     * Exception path: issuing a post-issuance status update without any associated status list entries
     * must fail.
     */
    @Test
    void updateStatusListsForPostIssuance_shouldThrowWhenNoStatusListsFound() {
        var emptySet = Set.<CredentialOfferStatus>of();

        var ex = assertThrows(BadRequestException.class,
                () -> statusListManagementService.updateStatusListsForPostIssuance(
                        emptySet, CredentialStatusManagementType.REVOKED));

        assertTrue(ex.getMessage().toLowerCase(Locale.ROOT).contains("no associated status lists"));
        verifyNoInteractions(statusListService);
    }

    /**
     * Exception path: unsupported transitions (e.g. INIT) must fail with a clear error.
     */
    @Test
    void updateStatusListsForPostIssuance_shouldThrowForInvalidTransition() {
        var offerStatusSet = Set.of(CredentialOfferStatus.builder()
                .id(CredentialOfferStatusKey.builder()
                        .offerId(UUID.randomUUID())
                        .statusListId(UUID.randomUUID())
                        .index(1)
                        .build())
                .build());

        var ex = assertThrows(BadRequestException.class,
                () -> statusListManagementService.updateStatusListsForPostIssuance(
                        offerStatusSet, CredentialStatusManagementType.INIT));

        assertTrue(ex.getMessage().contains("Illegal state transition"));
        verifyNoInteractions(statusListService);
    }

    /**
     * Edge case: if the underlying {@link StatusListService} returns an empty list, the service should
     * return it as-is.
     */
    @Test
    void updateStatusListsForPostIssuance_shouldReturnEmptyListIfStatusListServiceReturnsEmpty() {
        var offerStatusSet = Set.of(CredentialOfferStatus.builder()
                .id(CredentialOfferStatusKey.builder()
                        .offerId(UUID.randomUUID())
                        .statusListId(UUID.randomUUID())
                        .index(1)
                        .build())
                .build());

        when(statusListService.revoke(offerStatusSet)).thenReturn(List.of());

        var result = statusListManagementService.updateStatusListsForPostIssuance(
                offerStatusSet, CredentialStatusManagementType.REVOKED);

        assertNotNull(result);
        assertTrue(result.isEmpty());
        verify(statusListService).revoke(offerStatusSet);
        verifyNoMoreInteractions(statusListService);
    }
}
