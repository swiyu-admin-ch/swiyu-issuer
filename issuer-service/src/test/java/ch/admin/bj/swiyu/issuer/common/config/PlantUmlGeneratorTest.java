package ch.admin.bj.swiyu.issuer.common.config;

import ch.admin.bj.swiyu.issuer.common.PlantUmlExporter;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.statemachine.StateMachine;

import java.io.FileWriter;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertTrue;

class PlantUmlGeneratorTest {
    @Test
    void exportStateMachinesToPlantUmlFiles() throws Exception {
        AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(CredentialStateMachineConfig.class);

        // Zielverzeichnis für PlantUML-Dateien
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

    private static <S, E> boolean exportToFile(StateMachine<S, E> stateMachine, String fileName) throws IOException {
        PlantUmlExporter<S, E> exporter = new PlantUmlExporter<>();
        String plantUml = exporter.export(stateMachine);
        try (FileWriter writer = new FileWriter(fileName)) {
            writer.write(plantUml);
        }
        return new java.io.File(fileName).exists();
    }
}
