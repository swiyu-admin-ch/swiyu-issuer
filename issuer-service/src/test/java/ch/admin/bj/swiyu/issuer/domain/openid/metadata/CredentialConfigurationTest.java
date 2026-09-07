package ch.admin.bj.swiyu.issuer.domain.openid.metadata;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CredentialConfigurationTest {

    @Test
    void getCredentialRefreshDisabled_true_false_and_null() {
        var credentialConfiguration = new CredentialConfiguration();

        credentialConfiguration.setCredentialRefreshDisabled(Boolean.TRUE);
        assertThat(credentialConfiguration.getCredentialRefreshDisabled()).isTrue();

        credentialConfiguration.setCredentialRefreshDisabled(Boolean.FALSE);
        assertThat(credentialConfiguration.getCredentialRefreshDisabled()).isFalse();

        credentialConfiguration.setCredentialRefreshDisabled(null);
        assertThat(credentialConfiguration.getCredentialRefreshDisabled()).isFalse();
    }
}
