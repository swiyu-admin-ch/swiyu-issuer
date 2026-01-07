package ch.admin.bj.swiyu.issuer.common.config;

import ch.admin.bj.swiyu.issuer.common.PlantUmlExporter;
import ch.admin.bj.swiyu.issuer.domain.credentialoffer.CredentialStateMachineConfig;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.statemachine.StateMachine;

import java.io.FileWriter;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test for exporting state machines to PlantUML files.
 */
class PlantUmlGeneratorTest {

    /**
     * Exports state machines to PlantUML files and verifies the files are created.
     *
     * @throws Exception if export fails
     */
    @Test
    void exportStateMachinesToPlantUmlFiles() throws Exception {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(CredentialStateMachineConfig.class);

        // Target directory for PlantUML files
        String outputDir = "src/main/resources/plantuml/";
        java.nio.file.Files.createDirectories(java.nio.file.Paths.get(outputDir));

        // Export CredentialManagementStateMachine
        StateMachine<?, ?> credentialManagementStateMachine =
                context.getBean("credentialManagementStateMachine", StateMachine.class);
        boolean mgmtExported = exportToFile(credentialManagementStateMachine, outputDir + "credentialManagementStateMachine.puml");

        // Export CredentialOfferStateMachine
        StateMachine<?, ?> credentialOfferStateMachine =
                context.getBean("credentialOfferStateMachine", StateMachine.class);
        boolean offerExported = exportToFile(credentialOfferStateMachine, outputDir + "credentialOfferStateMachine.puml");

        context.close();
        assertTrue(mgmtExported, "credentialManagementStateMachine.puml should be written");
        assertTrue(offerExported, "credentialOfferStateMachine.puml should be written");
    }

    /**
     * Exports a state machine to a PlantUML file.
     *
     * @param stateMachine the state machine to export
     * @param fileName the output file name
     * @return true if file exists after export
     * @throws IOException if writing fails
     */
    private static <S, E> boolean exportToFile(StateMachine<S, E> stateMachine, String fileName) throws IOException {
        PlantUmlExporter<S, E> exporter = new PlantUmlExporter<>();
        String plantUml = exporter.export(stateMachine);
        try (FileWriter writer = new FileWriter(fileName)) {
            writer.write(plantUml);
        }
        return new java.io.File(fileName).exists();
    }
}
