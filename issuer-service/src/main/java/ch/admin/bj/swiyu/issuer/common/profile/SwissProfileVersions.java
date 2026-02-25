package ch.admin.bj.swiyu.issuer.common.profile;

import lombok.experimental.UtilityClass;

/**
 * Central place for Swiss Profile version indications.
 *
 * <p>Per "Versioning Indications in Swiss Profile":
 * <ul>
 *   <li>In JWTs the versioning attribute {@code profile_version} goes into the JWT header.</li>
 *   <li>In regular JSON bodies the versioning attribute {@code profile_version} goes into the JSON body.</li>
 * </ul>
 */
@UtilityClass
public final class SwissProfileVersions {

    /**
     * Swiss Profile indication for issuance / OAuth components (issuer- and authorization-server metadata, DPoP, ...).
     */
    public static final String ISSUANCE_PROFILE_VERSION = "swiss-profile-issuance:1.0.0";

    /**
     * Swiss Profile indication for verifiable credential artifacts (status list tokens, SD-JWT, ...).
     */
    public static final String VC_PROFILE_VERSION = "swiss-profile-vc:1.0.0";

    /**
     * JSON/JWT-header parameter name.
     */
    public static final String PROFILE_VERSION_PARAM = "profile_version";
}

