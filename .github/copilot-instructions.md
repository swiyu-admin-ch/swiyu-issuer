# Copilot Instructions (Project Guidelines)

This file defines mandatory project guidelines that GitHub Copilot should follow when generating code, suggesting refactorings, or proposing changes in this repository.

## Technology Baseline
- **Rule:** Prefer Spring Boot conventions and Spring-managed beans for application components.
- **Guideline:** Lombok is allowed and commonly used in this codebase.
  - **Prefer:** Lombok where it clearly improves readability and reduces boilerplate (e.g., `@Slf4j`, `@RequiredArgsConstructor`).
  - **Avoid:** Adding Lombok annotations by default or “just because”. If plain Java is equally clear (or clearer), prefer explicit code.

## Clean Code – Core Principles

### 1) Separation of Concerns (SoC)
- **Rule:** Each class/module focuses on **one clearly scoped responsibility**.
- **Avoid:** "God classes" that mix concerns such as authentication, persistence, and notifications.
- **Prefer:** Split responsibilities into dedicated components/services/repositories.

### 2) Single Responsibility Principle (SRP)
- **Rule:** A class should have **only one reason to change**.
- **Implication:** If changes happen for different reasons (e.g., calculation vs. reporting), split into separate units.

### 3) High Cohesion
- **Rule:** A class’s fields and methods should all serve the **same core purpose**.
- **Avoid:** Unrelated helper/utility logic inside domain or service classes.

### 4) Low Coupling
- **Rule:** Keep dependencies between classes as small as possible.
- **Prefer:** Dependency Injection, interfaces/ports, and clear abstractions.
- **Avoid:** Tight coupling like directly creating infrastructure dependencies (e.g., `new DatabaseConnection()`) inside services.

### 5) Small, Focused Classes & Methods
- **Rule:** Classes should typically fit on **one screen (~200 LOC)**.
- **Rule:** Methods should be short, well-named, and perform **one logical task**.
- **Hint:** If a method mixes validation + mapping + I/O + logging + business rules → split it.

## JavaDoc & Documentation

### Mandatory Scope
- **Rule:** Every **public** class, **public** interface, and **public** method must have JavaDoc.

### Content Guidelines
- **Focus:** Explain *why it exists* and *what it does* (intent), not internal implementation details.
- **Keep it updated:** Update JavaDoc whenever behavior/logic changes.
- **Avoid:** Redundant comments like “gets the name” for `getName()`.

### Language
- **Rule:** **All JavaDoc and code comments must be written in English.**

## Spring / Dependency Injection

### Constructor Injection Only (No Field Injection)
- **Rule:** Do **not** use field injection (e.g., `@Autowired` on fields).
- **Prefer:** Constructor injection with `final` fields.

### Lombok Conventions
- **Prefer:** `@RequiredArgsConstructor` with `final` dependencies.
- **Avoid:** `@AllArgsConstructor` on Spring beans when it’s not needed.
- **Rule:** Dependencies in Spring beans (controllers/services/components) must be `final`.

### Stateless Services and Components
- **Rule:** Spring beans annotated with `@Service` or `@Component` must be **stateless**.
- **Implementation:** Use **only `final` fields**; do not introduce mutable shared state.

## Architecture & Naming (Repository-Enforced Rules)

### Respect Package Layers
- **Rule:** Place new classes in the correct package (e.g., `..domain..`, `..dto..`, `..service..`, `..common..`, `..web..`).
- **Rule:** Do not introduce layer violations (keep dependencies aligned with the existing architecture tests).

### Prefer Service Orchestration Over Fat Controllers
- **Rule:** Controllers should handle HTTP-specific concerns (headers, status codes, request parsing, basic validation).
- **Prefer:** Put orchestration/business logic into dedicated services/facades (e.g., orchestrator services).

### Controller Style
- **Prefer:** `ResponseEntity<T>` when the endpoint needs to control status codes and/or headers explicitly.
- **Prefer:** Header constants for repeated header names (e.g., DPoP header).
- **Prefer:** Delegate business rules to services; controllers should not contain complex branching logic.

### Naming Conventions
- **Rule:** `@RestController` classes must:
  - live in `..web..`
  - end with `Controller`
- **Rule:** `@Service` classes must end with `Service` and live in `..service..`.
- **Rule:** `@Repository` classes must end with `Repository` and follow the repo’s package conventions.

### Interface Naming
- **Rule:** Do not name interfaces with `*Interface` suffix or names containing `Interface`.

## Logging & Error Handling
- **Prefer:** `@Slf4j` and structured logging (include identifiers/keys).
- **Rule:** Avoid logging secrets (tokens, credentials, private keys).

## Testing
- **Prefer:** Spring `MockMvc` for web layer tests.
- **Prefer:** Assertions with `andExpect(status().is...())` and `jsonPath(...)` for response bodies.
- **Rule:** Add/adjust tests when changing externally observable behavior.

## What Copilot Should Keep in Mind
- For new features/changes, always ask: **Where does this responsibility belong?**
- For refactorings, prefer small, safe steps; avoid unnecessary large reorganizations.
- **When unsure, ask before introducing new dependencies or proposing architectural changes.**
- Keep public APIs stable (only change signatures when necessary) and adjust/add tests.
