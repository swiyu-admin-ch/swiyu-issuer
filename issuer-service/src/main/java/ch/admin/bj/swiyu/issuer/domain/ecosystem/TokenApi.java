/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.domain.ecosystem;

import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.service.annotation.PostExchange;

/**
 * The API which is provided by the token provider of the swiyu ecosystem api
 * components.
 */
public interface TokenApi {

    @PostExchange(contentType = "application/x-www-form-urlencoded")
    TokenResponse getNewToken(

            @RequestParam String client_id,
            @RequestParam String client_secret,
            @RequestParam String grant_type);

    @PostExchange(contentType = "application/x-www-form-urlencoded")
    TokenResponse getNewToken(
            @RequestParam String client_id,
            @RequestParam String client_secret,
            @RequestParam(required = false) String refresh_token,
            @RequestParam String grant_type);

    record TokenResponse(
            String access_token,
            String refresh_token) {
    }
}