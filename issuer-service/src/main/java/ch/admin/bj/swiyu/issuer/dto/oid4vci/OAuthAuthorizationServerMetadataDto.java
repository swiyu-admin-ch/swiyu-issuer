package ch.admin.bj.swiyu.issuer.dto.oid4vci;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.annotation.Nullable;
import lombok.Builder;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(name = "OAuthAuthorizationServerMetadata")
@Builder(toBuilder = true)
public record OAuthAuthorizationServerMetadataDto(String issuer, String token_endpoint,
                                                  @Nullable List<String> dpop_signing_alg_values_supported) {

}
