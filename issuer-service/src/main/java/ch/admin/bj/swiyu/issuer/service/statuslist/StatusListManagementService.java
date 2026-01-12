package ch.admin.bj.swiyu.issuer.service.statuslist;

import ch.admin.bj.swiyu.issuer.api.credentialoffer.CreateCredentialOfferRequestDto;
import ch.admin.bj.swiyu.issuer.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatus;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusManagementType;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusList;
import ch.admin.bj.swiyu.issuer.service.StatusListService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Service responsible for status list management operations.
 *
 * <p>This service handles status list resolution, validation, and status updates
 * for credential offers.</p>
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class StatusListManagementService {

    private final StatusListService statusListService;

    /**
     * Resolves and validates status lists from a credential offer request.
     *
     * @param request the credential offer request
     * @return the list of resolved status lists
     * @throws BadRequestException if not all status lists can be resolved
     */
    public List<StatusList> resolveAndValidateStatusLists(CreateCredentialOfferRequestDto request) {
        var statusListUris = request.getStatusLists();
        var statusLists = statusListService.findByUriIn(statusListUris);

        if (statusLists.size() != request.getStatusLists().size()) {
            throw new BadRequestException(
                    "Could not resolve all provided status lists, only found %s"
                            .formatted(statusLists.stream()
                                    .map(StatusList::getUri)
                                    .collect(Collectors.joining(", "))));
        }

        return statusLists;
    }

    /**
     * Updates status lists for post-issuance status changes.
     *
     * @param offerStatusSet the set of credential offer statuses
     * @param newStatus the new status to apply
     * @return the list of affected status list IDs
     * @throws BadRequestException if the status transition is invalid or no status lists are found
     */
    public List<UUID> updateStatusListsForPostIssuance(
            Set<CredentialOfferStatus> offerStatusSet,
            CredentialStatusManagementType newStatus) {

        if (offerStatusSet.isEmpty()) {
            throw new BadRequestException(
                    "No associated status lists found. Can not set a status to an already issued credential");
        }

        return switch (newStatus) {
            case REVOKED -> statusListService.revoke(offerStatusSet);
            case SUSPENDED -> statusListService.suspend(offerStatusSet);
            case ISSUED -> statusListService.revalidate(offerStatusSet);
            default -> throw new BadRequestException(
                    "Illegal state transition - Status cannot be updated to %s".formatted(newStatus));
        };
    }
}

