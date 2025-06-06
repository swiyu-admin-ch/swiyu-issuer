/*
 * SPDX-FileCopyrightText: 2025 Swiss Confederation
 *
 * SPDX-License-Identifier: MIT
 */

package ch.admin.bj.swiyu.issuer.domain.openid.metadata;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class CredentialClaim {
    /**
     * Optional, if set to true the claim is mandatory in the presentation
     */
    private boolean mandatory;
    /**
     * Optional, if set should be one of:
     * <ul>
     * <li>string</li>
     * <li>number</li>
     * <li><a href="https://www.iana.org/assignments/media-types/media-types.xhtml#image">iana data type</a></li>
     * </ul>
     */
    @JsonProperty("value_type")
    private String valueType;

}
