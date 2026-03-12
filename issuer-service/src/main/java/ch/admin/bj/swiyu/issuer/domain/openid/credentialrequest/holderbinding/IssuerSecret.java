package ch.admin.bj.swiyu.issuer.domain.openid.credentialrequest.holderbinding;

import java.util.UUID;

import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.params.KeyParameter;

import ch.admin.bj.swiyu.issuer.common.crypto.HashUtil;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Builder
@Getter
@Setter
@NoArgsConstructor(access = AccessLevel.PROTECTED) // JPA
@AllArgsConstructor
public class IssuerSecret {
    
    @Id
    private UUID id; // Doubles as the secret

    public KeyParameter getAsKeyParameter() {
        return new KeyParameter(id.toString().getBytes());
    }
}
