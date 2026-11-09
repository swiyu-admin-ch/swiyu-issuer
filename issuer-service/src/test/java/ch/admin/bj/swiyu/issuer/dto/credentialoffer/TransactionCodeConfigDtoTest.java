package ch.admin.bj.swiyu.issuer.dto.credentialoffer;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import tools.jackson.databind.cfg.ConstructorDetector;
import tools.jackson.databind.json.JsonMapper;

import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

class TransactionCodeConfigDtoTest {

    private static final String REQUEST_WITHOUT_TX_CODE_LENGTH = """
            {
                "tx_code_config": {
                    "use_tx_code": true
                }
            }
            """;

    private static Stream<Arguments> mappers() {
        return Stream.of(
                Arguments.of("default detector", JsonMapper.builder().build()),
                Arguments.of("properties-based detector",
                        JsonMapper.builder().constructorDetector(ConstructorDetector.USE_PROPERTIES_BASED).build())
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("mappers")
    void deserialization_shouldApplyDefaultLength_whenLengthIsOmitted(String configuration, JsonMapper mapper) {
        var request = mapper.readValue(REQUEST_WITHOUT_TX_CODE_LENGTH, CreateCredentialOfferRequestDto.class);

        assertThat(request.getTransactionCodeConfig()).isNotNull();
        assertThat(request.getTransactionCodeConfig().isUseTransactionCode())
                .as("use_tx_code must be taken from the payload (mapper: %s)", configuration)
                .isTrue();
        assertThat(request.getTransactionCodeConfig().getLength())
                .as("length must default to 6 when omitted (mapper: %s)", configuration)
                .isEqualTo(6);
        assertThat(request.getTransactionCodeConfig().getDescription()).isNull();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("mappers")
    void deserialization_shouldApplyDefaultFlag_whenUseTxCodeIsOmitted(String configuration, JsonMapper mapper) {
        var request = mapper.readValue("{\"tx_code_config\": {}}", CreateCredentialOfferRequestDto.class);

        assertThat(request.getTransactionCodeConfig().isUseTransactionCode())
                .as("use_tx_code must default to false when omitted (mapper: %s)", configuration)
                .isFalse();
        assertThat(request.getTransactionCodeConfig().getLength())
                .as("length must default to 6 when omitted (mapper: %s)", configuration)
                .isEqualTo(6);
    }

    @Test
    void deserialization_shouldKeepProvidedValues() {
        var mapper = JsonMapper.builder().constructorDetector(ConstructorDetector.USE_PROPERTIES_BASED).build();
        var request = mapper.readValue("""
                {"tx_code_config": {"use_tx_code": true, "description": "Sent by SMS", "length": 4}}
                """, CreateCredentialOfferRequestDto.class);

        assertThat(request.getTransactionCodeConfig().isUseTransactionCode()).isTrue();
        assertThat(request.getTransactionCodeConfig().getDescription()).isEqualTo("Sent by SMS");
        assertThat(request.getTransactionCodeConfig().getLength()).isEqualTo(4);
    }

    @Test
    void builder_shouldApplyDefaultLength_whenLengthIsNotSet() {
        var config = TransactionCodeConfigDto.builder().useTransactionCode(true).build();

        assertThat(config.getLength()).isEqualTo(6);
        assertThat(config.isUseTransactionCode()).isTrue();
    }
}