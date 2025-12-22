package ch.admin.bj.swiyu.issuer.common;

import org.springframework.statemachine.StateMachine;
import org.springframework.statemachine.state.State;
import org.springframework.statemachine.transition.Transition;

public class PlantUmlExporter<S, E> {
    public String export(StateMachine<S, E> stateMachine) {
        StringBuilder sb = new StringBuilder();
        sb.append("@startuml\n");

        for (State<S, E> state : stateMachine.getStates()) {
            if ("INIT".equals(String.valueOf(state.getId()))) continue; // INIT nicht als eigenen State ausgeben
            sb.append("state ").append(state.getId()).append("\n");
        }
        for (Transition<S, E> transition : stateMachine.getTransitions()) {
            if (transition.getSource() != null && transition.getTarget() != null) {
                String sourceId = String.valueOf(transition.getSource().getId());
                String targetId = String.valueOf(transition.getTarget().getId());
                String from = "INIT".equals(sourceId) ? "[*]" : sourceId;
                String to = "INIT".equals(targetId) ? "[*]" : targetId;
                sb.append(from)
                  .append(" --> ")
                  .append(to);
                if (transition.getTrigger() != null && transition.getTrigger().getEvent() != null) {
                    Object event = transition.getTrigger().getEvent();
                    String label;
                    try {
                        label = (String) event.getClass().getMethod("getDisplayName").invoke(event);
                    } catch (Exception ex) {
                        label = event.toString();
                    }
                    sb.append(" : ").append(label);
                }
                sb.append("\n");
            }
        }
        sb.append("@enduml\n");
        return sb.toString();
    }
}
