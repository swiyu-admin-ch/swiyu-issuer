package ch.admin.bj.swiyu.issuer.common;

import org.springframework.statemachine.StateMachine;
import org.springframework.statemachine.state.State;
import org.springframework.statemachine.transition.Transition;

/**
 * Utility to export a Spring StateMachine to PlantUML format.
 *
 * @param <S> State type
 * @param <E> Event type
 */
public class PlantUmlExporter<S, E> {

    /**
     * Exports the given state machine as a PlantUML diagram.
     *
     * @param stateMachine the state machine to export
     * @return PlantUML diagram as a String
     */
    public String export(StateMachine<S, E> stateMachine) {
        StringBuilder sb = new StringBuilder(64);
        sb.append("@startuml\n");
        appendStates(sb, stateMachine);
        appendTransitions(sb, stateMachine);
        sb.append("@enduml\n");
        return sb.toString();
    }

    /**
     * Appends all states to the PlantUML diagram.
     *
     * @param sb StringBuilder for the diagram
     * @param stateMachine the state machine
     */
    private void appendStates(StringBuilder sb, StateMachine<S, E> stateMachine) {
        for (State<S, E> state : stateMachine.getStates()) {
            // Do not output INIT as a separate state
            if ("INIT".equals(String.valueOf(state.getId()))) continue;
            sb.append("state ").append(state.getId()).append('\n');
        }
    }

    /**
     * Appends all transitions to the PlantUML diagram.
     *
     * @param sb StringBuilder for the diagram
     * @param stateMachine the state machine
     */
    private void appendTransitions(StringBuilder sb, StateMachine<S, E> stateMachine) {
        for (Transition<S, E> transition : stateMachine.getTransitions()) {
            appendTransaction(sb, transition);
        }
    }

    /**
     * Appends a single transition to the PlantUML diagram.
     *
     * @param sb StringBuilder for the diagram
     * @param transition the transition
     */
    private void appendTransaction(StringBuilder sb, Transition<S, E> transition) {
        if (transition.getSource() != null && transition.getTarget() != null) {
            String sourceId = String.valueOf(transition.getSource().getId());
            String targetId = String.valueOf(transition.getTarget().getId());
            String from = "INIT".equals(sourceId) ? "[*]" : sourceId;
            String to = "INIT".equals(targetId) ? "[*]" : targetId;
            sb.append(from)
                    .append(" --> ")
                    .append(to);
            String label = getTransitionLabel(transition);
            if (!label.isEmpty()) {
                sb.append(" : ").append(label);
            }
            String transitionNameAnnotation = getTransitionNameAnnotation(transition);
            if (!transitionNameAnnotation.isEmpty()) {
                sb.append("\\n").append(transitionNameAnnotation);
            }
            sb.append('\n');
        }
    }

    /**
     * Gets the label for a transition, using getDisplayName if available.
     *
     * @param transition the transition
     * @return label for the transition
     */
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private String getTransitionLabel(Transition<S, E> transition) {
        if (transition.getTrigger() != null && transition.getTrigger().getEvent() != null) {
            Object event = transition.getTrigger().getEvent();
            try {
                return (String) event.getClass().getMethod("getDisplayName").invoke(event);
            } catch (Exception ex) {
                return event.toString();
            }
        }
        return "";
    }

    /**
     * Gets the name annotation for a transition if present.
     *
     * @param transition the transition
     * @return name annotation or empty string
     */
    private String getTransitionNameAnnotation(Transition<S, E> transition) {
        if (transition.getName() != null) {
            return transition.getName();
        }
        return "";
    }
}
