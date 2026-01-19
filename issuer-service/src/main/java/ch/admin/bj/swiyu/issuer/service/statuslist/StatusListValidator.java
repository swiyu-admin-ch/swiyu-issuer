package ch.admin.bj.swiyu.issuer.service.statuslist;

import ch.admin.bj.swiyu.issuer.api.credentialoffer.CreateCredentialOfferRequestDto;
import ch.admin.bj.swiyu.issuer.common.exception.BadRequestException;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialOfferStatus;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStatusManagementType;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.StatusList;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.TokenStatusListBit;
import lombok.experimental.UtilityClass;

import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * Stateless validation/guard helpers for status list use-cases.
 *
 * <p>Only performs input/state validation and throws domain-specific exceptions.
 * It must not perform persistence, locking, IO, or external calls.</p>
 */
@UtilityClass
public class StatusListValidator {

    /**
     * Ensures that all status list URIs provided in the request could be resolved.
     *
     * @param request  offer request containing the expected status list URIs
     * @param resolved resolved status lists
     * @return the resolved list (unchanged)
     * @throws BadRequestException if not all status list URIs could be resolved
     */
    public List<StatusList> requireAllStatusListsResolved(CreateCredentialOfferRequestDto request, List<StatusList> resolved) {
        var expectedUris = request.getStatusLists();
        if (resolved.size() != expectedUris.size()) {
            throw new BadRequestException(
                    "Could not resolve all provided status lists, only found %s"
                            .formatted(resolved.stream()
                                    .map(StatusList::getUri)
                                    .collect(Collectors.joining(", "))));
        }
        return resolved;
    }

    /**
     * Ensures that there are status list entries associated with the credential(s) to update.
     *
     * @param offerStatusSet offer status entries
     * @throws BadRequestException if the set is empty
     */
    public void requireOfferStatusesPresent(Set<CredentialOfferStatus> offerStatusSet) {
        if (offerStatusSet.isEmpty()) {
            throw new BadRequestException(
                    "No associated status lists found. Can not set a status to an already issued credential");
        }
    }

    /**
     * Validates the requested post-issuance status transition and maps it to the appropriate action.
     *
     * @param newStatus   requested new management status
     * @param revoke      action for {@link CredentialStatusManagementType#REVOKED}
     * @param suspend     action for {@link CredentialStatusManagementType#SUSPENDED}
     * @param revalidate  action for {@link CredentialStatusManagementType#ISSUED} (re-validate)
     * @return affected status list IDs
     * @throws BadRequestException if the transition is not supported
     */
    public List<UUID> validateAndMapPostIssuanceTransition(
            CredentialStatusManagementType newStatus,
            Supplier<List<UUID>> revoke,
            Supplier<List<UUID>> suspend,
            Supplier<List<UUID>> revalidate) {

        return switch (newStatus) {
            case REVOKED -> revoke.get();
            case SUSPENDED -> suspend.get();
            case ISSUED -> revalidate.get();
            default -> throw new BadRequestException(
                    "Illegal state transition - Status cannot be updated to %s".formatted(newStatus));
        };
    }

    /**
     * Ensures that a status list supports the requested status bit.
     *
     * @param statusListBits configured bits per entry
     * @param bit            requested bit
     * @param statusListUri  uri used for error messages
     * @throws BadRequestException if the bit is not supported by the status list
     */
    public void requireBitSupported(int statusListBits, TokenStatusListBit bit, String statusListUri) {
        if (statusListBits < bit.getValue()) {
            throw new BadRequestException(
                    String.format("Attempted to update a status list %s to a status not supported %s", statusListUri, bit.name()));
        }
    }


}
