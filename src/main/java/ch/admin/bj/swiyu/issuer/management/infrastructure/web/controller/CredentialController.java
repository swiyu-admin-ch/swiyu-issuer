/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.management.infrastructure.web.controller;

import java.util.UUID;

import static ch.admin.bj.swiyu.issuer.management.service.CredentialOfferMapper.toCredentialWithDeeplinkResponseDto;
import static ch.admin.bj.swiyu.issuer.management.service.CredentialOfferMapper.toUpdateStatusResponseDto;
import static ch.admin.bj.swiyu.issuer.management.service.statusregistry.StatusResponseMapper.toStatusResponseDto;

import ch.admin.bj.swiyu.issuer.management.api.credentialoffer.CreateCredentialRequestDto;
import ch.admin.bj.swiyu.issuer.management.api.credentialoffer.CredentialWithDeeplinkResponseDto;
import ch.admin.bj.swiyu.issuer.management.api.credentialofferstatus.CredentialStatusTypeDto;
import ch.admin.bj.swiyu.issuer.management.api.credentialofferstatus.StatusResponseDto;
import ch.admin.bj.swiyu.issuer.management.api.credentialofferstatus.UpdateStatusResponseDto;
import ch.admin.bj.swiyu.issuer.management.service.CredentialService;
import io.micrometer.core.annotation.Timed;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping(value = {"/api/v1/credentials"})
@AllArgsConstructor
@Tag(name = "Credential", description = "Credential Management API")
public class CredentialController {

    private final CredentialService credentialService;

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
    public CredentialWithDeeplinkResponseDto createCredential(@Valid @RequestBody CreateCredentialRequestDto request) {
        return this.credentialService.createCredential(request);
    }

    @Timed
    @GetMapping("/{credentialId}")
    @Operation(
            summary = "Get the offer data, if any is still cached",
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Credential offer found",
                            content = @Content(
                                    schema = @Schema(implementation = Object.class),
                                    examples = {
                                            @ExampleObject(
                                                    name = "Offer data",
                                                    summary = "Example of vc content/ offer data for vc with first/lastname as credentialSubjectData",
                                                    value = """
                                                            {"lastName":"Example","firstName":"Edward"}
                                                            """
                                            )
                                    }
                            )
                    )
            }
    )
    public Object getCredentialOffer(@PathVariable UUID credentialId) {
        return this.credentialService.getCredentialOffer(credentialId);
    }

    @Timed
    @GetMapping("/{credentialId}/offer_deeplink")
    @Operation(
            summary = "Get the offer deeplink",
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Offer deeplink found",
                            content = @Content(
                                    schema = @Schema(implementation = String.class),
                                    examples = {
                                            @ExampleObject(
                                                    name = "Offer deeplink",
                                                    summary = "Example of a deeplink",
                                                    value = "swiyu://?credential_offer=%7B%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22b614c966-0c1d-4636-9aec-e2496d242d25%22%7D%7D%2C%22credential_issuer%22%3A%22https%3A%2F%2Fissuer-agent-oid4vci-d.bit.admin.ch%22%2C%22credential_configuration_ids%22%3A%5B%22myIssuerMetadataCredentialSupportedId%22%5D%7D"
                                            )
                                    }
                            )
                    ),
                    @ApiResponse(
                            responseCode = "404",
                            description = "Offer not found or already expired",
                            content = @Content(schema = @Schema(implementation = Object.class))
                    )
            }
    )
    public String getCredentialOfferDeeplink(@PathVariable UUID credentialId) {
        return this.credentialService.getCredentialOfferDeeplink(credentialId);
    }

    @Timed
    @GetMapping("/{credentialId}/status")
    @Operation(summary = "Get the current status of an offer or the verifiable credential, if already issued.")
    public StatusResponseDto getCredentialStatus(@PathVariable UUID credentialId) {
        return this.credentialService.getCredentialStatus(credentialId);
    }

    @Timed
    @PatchMapping("/{credentialId}/status")
    @Operation(summary = "Set the status of an offer or the verifiable credential associated with the id.")
    public UpdateStatusResponseDto updateCredentialStatus(@PathVariable UUID credentialId,
                                                          @Parameter(in = ParameterIn.QUERY, schema = @Schema(implementation = CredentialStatusTypeDto.class))
                                                          @RequestParam("credentialStatus") CredentialStatusTypeDto credentialStatus) {

        return this.credentialService.updateCredentialStatus(credentialId, credentialStatus);
    }
}
