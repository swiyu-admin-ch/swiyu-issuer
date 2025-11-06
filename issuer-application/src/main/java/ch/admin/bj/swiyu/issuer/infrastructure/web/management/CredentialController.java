/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.infrastructure.web.management;

import ch.admin.bj.swiyu.issuer.api.credentialoffer.CreateCredentialOfferRequestDto;
import ch.admin.bj.swiyu.issuer.api.credentialoffer.CredentialInfoResponseDto;
import ch.admin.bj.swiyu.issuer.api.credentialoffer.CredentialWithDeeplinkResponseDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.StatusResponseDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.UpdateCredentialStatusRequestTypeDto;
import ch.admin.bj.swiyu.issuer.api.credentialofferstatus.UpdateStatusResponseDto;
import ch.admin.bj.swiyu.issuer.service.CredentialManagementService;
import io.micrometer.core.annotation.Timed;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping(value = {"/management/api/credentials"})
@AllArgsConstructor
@Tag(name = "Credential API", description = "Exposes API endpoints for managing credential offers and their statuses. " +
        "Supports creating new credential offers, retrieving offer data and deeplinks, and updating or querying the " +
        "status of offers and issued verifiable credentials. (IF-114)")
public class CredentialController {

    private final CredentialManagementService credentialManagementService;

    @Timed
    @PostMapping("")
    @Operation(
            summary = "Create a generic credential offer with the given content",
            description = """
                    Create a new credential offer, which can the be collected by the holder.
                    The returned deep link has to be provided to the holder via an other channel, for example as QR-Code.
                    The credentialSubjectData can be a json object or a JWT, if the signer has been configured to perform data integrity checks.
                    Returns both the ID used to interact with the offer and later issued VC, and the deep link to be provided to
                    """,
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Credential offer created",
                            content = @Content(schema = @Schema(implementation = CredentialWithDeeplinkResponseDto.class))
                    ),
                    @ApiResponse(
                            responseCode = "400",
                            description = """
                                    Bad request due to user content or internal call to external service like statuslist
                                    """,
                            content = @Content(schema = @Schema(implementation = Object.class))
                    )
            }
    )
    public CredentialWithDeeplinkResponseDto createCredential(@Valid @RequestBody CreateCredentialOfferRequestDto request) {
        return this.credentialManagementService.createCredentialOfferAndGetDeeplink(request);
    }

    @Timed
    @GetMapping("/{credentialId}")
    @Operation(
            summary = "Get the offer data, if any is still cached",
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Credential offer found"
                    )
            }
    )
    public CredentialInfoResponseDto getCredentialInformation(@PathVariable UUID credentialId) {
        return this.credentialManagementService.getCredentialOfferInformation(credentialId);
    }

    @Deprecated(forRemoval = true)
    @Timed
    /**
     * Endpoint to retrieve the deeplink for a credential offer.
     * @deprecated Use {@link #getCredentialInformation(UUID)} instead. Which contains the deeplink in the response.
     */
    @GetMapping("/{credentialId}/offer_deeplink")
    public String getCredentialOfferDeeplink(@PathVariable UUID credentialId) {
        return this.credentialManagementService.getCredentialOfferDeeplink(credentialId);
    }

    @Timed
    @GetMapping("/{credentialId}/status")
    @Operation(summary = "Get the current status of an offer or the verifiable credential, if already issued.")
    public StatusResponseDto getCredentialStatus(@PathVariable UUID credentialId) {
        return this.credentialManagementService.getCredentialStatus(credentialId);
    }

    @Timed
    @PatchMapping("/{credentialId}")
    @Operation(summary = "Update the status of an offer or the verifiable credential associated with the id. This is only for deferred flows. The status is set to ready for issuance",
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Credential status updated",
                            content = @Content(schema = @Schema(implementation = UpdateStatusResponseDto.class))
                    ),
                    @ApiResponse(
                            responseCode = "400",
                            description = "Bad request due to user content or internal call to external service like statuslist",
                            content = @Content(schema = @Schema(implementation = Object.class))
                    )
            }
    )
    public UpdateStatusResponseDto updateCredentialForDeferredFlow(@PathVariable UUID credentialId, @RequestBody Map<String, Object> credentialOffer) {

        return this.credentialManagementService.updateOfferDataForDeferred(credentialId, credentialOffer);
    }

    @Timed
    @PatchMapping("/{credentialId}/status")
    @Operation(summary = "Set the status of an offer or the verifiable credential associated with the id.")
    public UpdateStatusResponseDto updateCredentialStatus(@PathVariable UUID credentialId,
                                                          @Parameter(in = ParameterIn.QUERY, schema = @Schema(implementation = UpdateCredentialStatusRequestTypeDto.class))
                                                          @RequestParam("credentialStatus") UpdateCredentialStatusRequestTypeDto credentialStatus) {

        return credentialManagementService.updateCredentialStatus(credentialId, credentialStatus);
    }
}