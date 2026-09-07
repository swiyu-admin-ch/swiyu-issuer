package ch.admin.bj.swiyu.issuer.common.config;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ApplicationPropertiesTest {

    @Test
    void isRenewalFlowEnabled_returnsTrue_whenDPoPEnforce_andEndpointSet() {
        ApplicationProperties props = new ApplicationProperties();
        props.setDpopEnforce(true);
        props.setBusinessIssuerRenewalApiEndpoint("https://example.org/renew");

        assertThat(props.isRenewalFlowEnabled()).isTrue();
    }

    @Test
    void isRenewalFlowEnabled_returnsFalse_whenDPoPNotEnforced() {
        ApplicationProperties props = new ApplicationProperties();
        props.setDpopEnforce(false);
        props.setBusinessIssuerRenewalApiEndpoint("https://example.org/renew");

        assertThat(props.isRenewalFlowEnabled()).isFalse();
    }

    @Test
    void isRenewalFlowEnabled_returnsFalse_whenEndpointMissing() {
        ApplicationProperties props = new ApplicationProperties();
        props.setDpopEnforce(true);
        props.setBusinessIssuerRenewalApiEndpoint(null);

        assertThat(props.isRenewalFlowEnabled()).isFalse();
    }
}
