package ch.admin.bj.swiyu.issuer.domain.openid.metadata;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import org.springframework.validation.annotation.Validated;

import java.util.Map;

@EqualsAndHashCode(callSuper = true)
@SuperBuilder(toBuilder = true)
@Data
@Validated
@JsonInclude(JsonInclude.Include.NON_NULL)
@AllArgsConstructor
@NoArgsConstructor
public class IssuerCredentialRequestEncryption extends IssuerCredentialEncryption {
    @JsonProperty("jwks")
    @Schema(description = "A JSON Web Key Set that contains one or more public keys, to be used by the Wallet as an input to a key agreement for encryption of the Credential Request.", example = """
            {
              "keys" : [ {
                "kty" : "EC",
                "crv" : "P-256",
                "kid" : "ec91e148-974d-47f1-9891-4b89d8bad57c",
                "x" : "rm2YkWAJ2V84gS00DqeGR6MXHgW3FWISG45Vop0cWv4",
                "y" : "ktSScp7s2fWSdq_7c6iOUI9AYFwQahXG60Nr9SL68mY"
              } ]
            }
            """)
    private Map<String, Object> jwks;


}
