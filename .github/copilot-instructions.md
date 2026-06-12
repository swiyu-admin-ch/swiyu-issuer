# Copilot Instructions (Project Guidelines)

This file defines mandatory project guidelines that GitHub Copilot should follow when generating code, suggesting
refactorings, or proposing changes in this repository.

## 1. Role & Persona

Act as an experienced Senior Software Engineer. You write clean, maintainable, performant, and secure code. Your
responses are precise, direct, and contain only the necessary context. Avoid unnecessary explanations unless explicitly
asked.

## 2. Technology Stack

- **Build & Project Structure**
    - **Build tool:** Maven (`pom.xml` in a multi-module setup, parent artifact `swiyu-issuer-parent` `3.1.1`)
    - **Modules:**
        - `issuer-service` – business logic, domain model, DTOs, shared configuration/utilities
        - `issuer-application` – Spring Boot application and web/infrastructure layer (depends on `issuer-service`)

- **Primary Programming Language**
    - **Java 21** (defined via `java.version` in the parent `pom.xml`)
    - No Kotlin runtime is required for this project.

- **Main Frameworks**
    - **Spring Boot 4.0.6** (parent: `spring-boot-starter-parent` `4.0.6`)
    - **Spring Cloud 2025.1.1** (BOM via `spring-cloud-dependencies`)
    - **Spring Framework / Spring Ecosystem**, including:
        - Spring Web (`spring-boot-starter-web`, in `issuer-application`)
        - Spring Security (`spring-boot-starter-security`, in `issuer-application`)
        - Spring Validation (`spring-boot-starter-validation`)
        - Spring Data JPA (`spring-boot-starter-data-jpa`)
        - Spring Actuator (`spring-boot-starter-actuator`, in `issuer-application`)
        - Spring OAuth2 Resource Server (`spring-boot-starter-oauth2-resource-server`, in `issuer-service`)
        - Spring WebClient (`spring-boot-starter-webclient`, in `issuer-application`)
        - Spring Cloud Kubernetes Config (`spring-cloud-starter-kubernetes-fabric8-config`, in `issuer-application`
          only)
        - Spring Cloud Bootstrap (`spring-cloud-starter-bootstrap`, in `issuer-application` only)
        - **Spring Statemachine 4.0.1** – used in `issuer-service` to drive the credential offer / issuance lifecycle.
        - Note: `spring-webflux` is a direct dependency of `issuer-service` (used by `WebClient` and reactive
          utilities), but the `spring-boot-starter-webflux` starter is **not** used — the web layer is Spring MVC.

- **Persistence & Database**
    - **PostgreSQL** as the primary database (`org.postgresql:postgresql`, runtime, version pinned to `42.7.11`)
    - **Hibernate / JPA** via Spring Data JPA
    - **HikariCP** as datasource pool (transitive via Spring Boot)
    - **Flyway** for database migrations (`spring-boot-starter-flyway`, `flyway-database-postgresql`)
        - Shared migrations: `issuer-application/src/main/resources/db/migration/common`
        - PostgreSQL-specific overrides: `issuer-application/src/main/resources/db/migration/postgres`

- **Important Libraries**
    - **Lombok** (`org.projectlombok:lombok`, marked optional) for reducing boilerplate
    - **Nimbus JOSE + JWT** (`10.8`) for JWT/JOSE processing
    - **Bouncy Castle** (`bcprov-jdk18on`, `bcpkix-jdk18on`, both `1.84`) for cryptographic support
    - **Authlete SD-JWT** (`com.authlete:sd-jwt`, `1.7`) for SD-JWT handling
    - **SpringDoc OpenAPI** (`springdoc-openapi-starter-webmvc-ui`, `3.0.0`) for OpenAPI/Swagger documentation;
      `springdoc-openapi-maven-plugin` is used to generate `openapi.yaml`.
    - **OpenAPI Generator Maven Plugin** (`7.19.0`) generates HTTP clients from external API specs (e.g.
      `swiyu-core-status-registry-api-client`, `swiyu-core-trust-sidechannel-api-client`).
    - **Micrometer + Prometheus** for metrics/monitoring
    - **Micrometer Tracing + Brave bridge** for distributed tracing
    - **ShedLock** (`6.0.2`, `shedlock-spring` + `shedlock-provider-jdbc-template`) for scheduled task locking; enabled
      via `@EnableSchedulerLock` on the application class.
    - **Caffeine** for in-memory caching (notably trust statement caching with per-entry TTL).
    - **JsonPath** (`2.10.0`) for JSON assertions and processing.
    - **Primus JCE** (`2.4.4`, system scope) – HSM provider integrated via the Spring Boot Maven plugin (
      `includeSystemScope=true`).
    - **DID / SWIYU-specific libraries** (all under group `ch.admin.swiyu`, currently version `1.6.4`):
        - `swiyu-jws-signature-service`
        - `swiyu-did-resolver-adapter`
        - `swiyu-jwe-util`
        - `swiyu-jwt-util`
        - `swiyu-jwt-validator`
        - `swiyu-dpop-util`
        - `swiyu-ts-builder` (test scope only in `issuer-application`, currently `1.5.0`)

- **Testing Frameworks & Test Utilities**
    - **JUnit 5** / Jupiter
    - **Spring Boot Test** (`spring-boot-starter-test`)
    - **Mockito** (provided through the Spring Boot Test stack)
    - **Spring Test / MockMvc** (`spring-boot-starter-webmvc-test`) for web layer and controller/integration tests
    - **Spring Data JPA Test** (`spring-boot-starter-data-jpa-test`) and **JDBC Test** for slice tests
    - **Testcontainers** for integration testing
        - JUnit Jupiter integration
        - PostgreSQL container support
        - MockServer container support
    - **MockServer** (`mockserver-client-java`, `5.15.0`) for HTTP stubbing in integration tests
    - **ArchUnit** (`archunit-junit5`, `1.4.1`) for architecture rules and package/layer validation

- **Build Quality / Verification Tooling**
    - **JaCoCo** (`0.8.14`) for test coverage
    - **PMD** (`maven-pmd-plugin` `3.27.0`) for static code analysis, configured via
      `.github/rulesets/java/pmd_omni_ruleset.xml`
    - **EditorConfig Maven Plugin** for style consistency
    - **Maven Surefire / Failsafe** for unit and integration test separation

### Spring Boot & Error Handling

#### Dependency Injection

- **Rule:** Do **not** use field injection (e.g., `@Autowired` on fields).
- **Prefer:** Constructor injection using Lombok's `@RequiredArgsConstructor` with `final` dependencies.
- **Avoid:** `@AllArgsConstructor` on Spring beans when not strictly needed.
- **Rule:** Dependencies in Spring beans (controllers/services/components) must be `final`.
- **Rule:** Spring beans annotated with `@Service` or `@Component` must be **stateless**. Do not introduce mutable
  shared state.

#### Lombok Conventions

- **Prefer:** Lombok where it clearly improves readability and reduces boilerplate (e.g., `@Slf4j`,
  `@RequiredArgsConstructor`).
- **Avoid:** Adding Lombok annotations by default or "just because". If plain Java is equally clear (or clearer), prefer
  explicit code.

#### Logging & Error Handling

- **Prefer:** Lombok's `@Slf4j` for logging.
- **Rule:** Use structured logging (include identifiers/keys).
- **Rule:** Never log secrets (tokens, credentials, private keys, PII).
- **Rule:** Handle errors gracefully. Throw clean, specific domain exceptions in the service layer, and translate them
  to proper HTTP responses (e.g., via `@ControllerAdvice`) in the web layer.

## 3. Clean Code – Core Principles

### 1) Separation of Concerns (SoC)

- **Rule:** Each class/module focuses on **one clearly scoped responsibility**.
- **Avoid:** "God classes" that mix concerns such as authentication, persistence, and notifications.
- **Prefer:** Split responsibilities into dedicated components/services/repositories.

### 2) Single Responsibility Principle (SRP)

- **Rule:** A class should have **only one reason to change**.
- **Implication:** If changes happen for different reasons (e.g., calculation vs. reporting), split into separate units.

### 3) High Cohesion

- **Rule:** A class's fields and methods should all serve the **same core purpose**.
- **Avoid:** Unrelated helper/utility logic inside domain or service classes.

### 4) Low Coupling

- **Rule:** Keep dependencies between classes as small as possible.
- **Prefer:** Dependency Injection, interfaces/ports, and clear abstractions.
- **Avoid:** Tight coupling like directly creating infrastructure dependencies (e.g., `new DatabaseConnection()`) inside
  services.

### 5) Small, Focused Classes & Methods

- **Rule:** Classes should typically fit on **one screen (~200 LOC)**.
- **Rule:** Methods should be short, well-named, and perform **one logical task**.
- **Hint:** If a method mixes validation + mapping + I/O + logging + business rules → split it.

### JavaDoc & Documentation

#### Mandatory Scope

- **Rule:** Every **public** class, **public** interface, and **public** method must have JavaDoc.

#### Content Guidelines

- **Focus:** Explain *why it exists* and *what it does* (intent), not internal implementation details.
- **Keep it updated:** Update JavaDoc whenever behavior/logic changes.
- **Avoid:** Redundant comments like "gets the name" for `getName()`.

#### Language

- **Rule:** **All JavaDoc and code comments must be written in English.**

## 4. Architecture & Project Structure

- **Rule:** This repository uses a **modular layered architecture** with a strong separation between:
    - **`issuer-application`** = application/bootstrap + infrastructure/web layer
    - **`issuer-service`** = business logic, domain model, DTOs, shared configuration/utilities

- **Guideline:** The dominant architectural style is **classical layered architecture** with clear package-based
  separation (`web`, `service`, `domain`, `dto`, `common`).
- **Note:** Credential lifecycle transitions are driven by **Spring Statemachine** in the service layer; treat the state
  machine definitions as part of the domain/service contract.

### Package Responsibilities

- **Web / Controller Layer**
    - **Rule:** HTTP controllers and web-specific concerns belong in `issuer-application` under:
        - `ch.admin.bj.swiyu.issuer.infrastructure.web.signer` – OID4VCI / public-facing endpoints (
          `WellKnownController`, `IssuanceController`, `CredentialMetadataController`)
        - `ch.admin.bj.swiyu.issuer.infrastructure.web.management` – internal management endpoints (
          `CredentialManagementController`, `StatusListController`)
    - **Rule:** Additional infrastructure-only concerns belong in `issuer-application` under packages such as:
        - `..infrastructure.config..`
        - `..infrastructure.security..`
        - `..infrastructure.scheduler..`
        - `..infrastructure.health..`
        - `..infrastructure.env..`
        - `..infrastructure.logging..`

- **Service / Business Logic Layer**
    - **Rule:** Business logic, orchestration, use cases, and integration-facing service abstractions belong in
      `issuer-service` under:
        - `ch.admin.bj.swiyu.issuer.service` (root: e.g. `CredentialServiceOrchestrator`, `OAuthService`,
          `AuthorizationService`, `NonceService`, `CredentialStateService`, `MetadataService`, `DataIntegrityService`)
        - `ch.admin.bj.swiyu.issuer.service.credential`
        - `ch.admin.bj.swiyu.issuer.service.did`
        - `ch.admin.bj.swiyu.issuer.service.dpop`
        - `ch.admin.bj.swiyu.issuer.service.enc` (`EncryptionKeyService`, `JweService`, `CacheMaintenanceService`)
        - `ch.admin.bj.swiyu.issuer.service.management`
        - `ch.admin.bj.swiyu.issuer.service.offer`
        - `ch.admin.bj.swiyu.issuer.service.persistence`
        - `ch.admin.bj.swiyu.issuer.service.renewal`
        - `ch.admin.bj.swiyu.issuer.service.statuslist` (`StatusListIndexService`, `StatusListPersistenceService`,
          `StatusListSigningService`)
        - `ch.admin.bj.swiyu.issuer.service.statusregistry` (`StatusRegistryTokenService`)
        - `ch.admin.bj.swiyu.issuer.service.trustregistry` (`TrustStatementInjectionService`,
          `TrustStatementCacheService`)
        - `ch.admin.bj.swiyu.issuer.service.webhook` (`EventProducerService`)

- **Repository / Persistence Layer**
    - **Rule:** Persistence lives in the **domain module/package area**, not in controllers.
    - **Rule:** Repository interfaces are currently located under `issuer-service` in:
        - `ch.admin.bj.swiyu.issuer.domain.credentialoffer` – `CredentialOfferRepository`,
          `CredentialManagementRepository`, `CredentialOfferStatusRepository`, `StatusListRepository`,
          `AvailableStatusListIndexRepository`
        - `ch.admin.bj.swiyu.issuer.domain.ecosystem` – `TokenSetRepository`
        - `ch.admin.bj.swiyu.issuer.domain.callback` – `CallbackEventRepository`
        - `ch.admin.bj.swiyu.issuer.domain.openid` – `EncryptionKeyRepository`, `CachedNonceRepository`,
          `IssuerSecretRepository`
    - **Rule:** JPA entities and persistence-backed aggregates remain in `..domain..` packages.

- **DTO Layer**
    - **Rule:** Transport and API-facing DTOs belong in `issuer-service` under `ch.admin.bj.swiyu.issuer.dto` and its
      subpackages.
    - **Rule:** DTOs must remain transport-focused and must not accumulate business logic.

- **Domain Model Layer**
    - **Rule:** Domain models, aggregates, value objects, and domain-specific repository contracts belong in:
        - `ch.admin.bj.swiyu.issuer.domain`
        - `ch.admin.bj.swiyu.issuer.domain.credentialoffer`
        - `ch.admin.bj.swiyu.issuer.domain.ecosystem`
        - `ch.admin.bj.swiyu.issuer.domain.callback`
        - `ch.admin.bj.swiyu.issuer.domain.openid`
    - **Rule:** Domain classes represent business concepts and rules, not HTTP or infrastructure concerns.

- **Shared / Common Layer**
    - **Rule:** Shared configuration, properties, exceptions, profiles, utilities, crypto helpers, and lock primitives
      belong in `ch.admin.bj.swiyu.issuer.common` and its subpackages (e.g. `common.crypto`, `common.locks`,
      `common.profiles`, `common.exception`).

### Layering and Dependency Rules

- **Rule:** Controllers must handle HTTP-specific concerns only:
    - request parsing
    - headers
    - response codes
    - basic validation
    - delegating to services
- **Rule:** Controllers must **not** access repositories directly.
- **Rule:** Controllers must **not** contain persistence logic or core business rules.
- **Rule:** Business orchestration belongs in `..service..` classes such as use cases, facades, and transactional
  services (e.g. `CredentialServiceOrchestrator`).
- **Rule:** Repository access must happen from the service/domain side, not from the web layer.
- **Rule:** Do not introduce dependencies from `issuer-service` to `issuer-application`.

- **Rule:** Respect the repository's existing ArchUnit constraints (see `ArchitectureTest` in `issuer-service` and
  `RestControllerHaveIFTagArchTest` in `issuer-application`):
    - layered architecture: `DTO → SERVICE` and `DOMAIN → SERVICE` (no reverse direction)
    - no cycles between `domain`, `common`, `dto`, and `service` slices
    - no field injection
    - no use of `java.util.logging` (use SLF4J / `@Slf4j`)
    - no generic exceptions thrown (use specific domain exceptions)
    - Spring services/components must be stateless and use final dependencies
    - `@RestController` classes must live in `..web..` and end with `Controller`
    - `@Service` classes must live in `..service..` and end with `Service`
    - `@Entity` classes must live in `..domain..`
    - `@Repository` classes must live in `..domain..` and end with `Repository`
    - classes ending with `Mapper` must be `@Service`s (mappers participate in DI)
    - interfaces must **not** be named with `*Interface` suffix or contain `Interface` in the name
    - every `@RestController` must carry a `@Tag` annotation with a unique `IF-xxx` interface code in its name (enforced
      for the public API documentation)
- **Guideline:** Both modules use ArchUnit freezing — when introducing intentional, justified rule deviations, refresh
  the frozen store deliberately rather than weakening the rule.

### Mapping Between Layers

- **Rule:** Mapping between HTTP/API DTOs, service models, and domain objects is done with **explicit mapper classes** (
  annotated `@Service`), not with ad-hoc conversion inside controllers.
- **Rule:** Prefer the existing manual mapping approach used in classes such as:
    - `CredentialMapper` (in `issuer-application` `..infrastructure.web..`)
    - `CredentialOfferMapper` (in `..service..`)
    - `CredentialManagementMapper` (in `..service..`)
    - `CredentialRequestMapper` (in `..service..`)
    - `CallbackMapper` (in `..service..`)
    - `StatusListMapper` (in `..service..`)
    - `StatusResponseMapper` (in `..service..`)
- **Rule:** Do **not** introduce MapStruct unless explicitly requested. No MapStruct-based mapping is used in the
  current repository.
- **Guideline:** Some mapping and normalization uses Jackson `ObjectMapper` internally where JSON transformation is part
  of the contract. Keep that logic centralized in dedicated mapper/resolver classes.

### Practical Copilot Guidance

- **Rule:** When adding a new endpoint, place the controller in `issuer-application` under
  `..infrastructure.web.signer..` (public/OID4VCI) or `..infrastructure.web.management..` (internal) and delegate
  immediately to a service.
- **Rule:** When adding business logic, prefer `issuer-service` under the appropriate `..service..` subpackage.
- **Rule:** When adding persistence-backed entities or repository contracts, place them in the relevant `..domain..`
  package.
- **Rule:** When adding request/response models, place them in `..dto..`.
- **Rule:** When converting between DTOs and domain objects, add or extend a dedicated `@Service`-annotated mapper
  instead of embedding mapping logic in controllers.
- **Rule:** Credential lifecycle changes belong in the existing Spring Statemachine flow under `..service..`; do not
  bypass it by mutating offer state directly from controllers or repositories.
- **Rule:** When integrating with external swiyu ecosystem services, prefer the generated OpenAPI clients (status
  registry, trust sidechannel) over ad-hoc HTTP code.
- **Rule:** Before generating code, always ask: **Is this web/infrastructure logic, service/use-case logic, domain
  logic, DTO mapping, or persistence?** Place it in the corresponding package and do not blur responsibilities.

### Controller Style

- **Prefer:** `ResponseEntity<T>` when the endpoint needs to control status codes and/or headers explicitly.
- **Prefer:** Header constants for repeated header names (e.g., DPoP header).
- **Prefer:** Delegate business rules to services; controllers should not contain complex branching logic.

## 5. Testing (Test Pyramid Philosophy)

We strictly follow the Test Pyramid. Copilot must adhere to the following scope, isolation, and naming rules when
generating or modifying tests.

### Unit Tests (Vast Majority of Tests)

- **Rule:** Isolate components completely. Always mock external dependencies (Databases, File Systems, External APIs).
- **Scope:** Exhaustively test business logic, including every `if` condition, loop, calculation, and edge case here.
- **Goal:** Tests must execute in milliseconds and pinpoint the exact failing method.
- **Coverage:** Do not generate code that decreases overall test coverage without a valid, documented reason.

### Integration Tests

- **Scope:** Only verify communication between interfaces/boundaries (e.g., "Does the endpoint call the service?" or "
  Does the SQL query work?").
- **Avoid:** Do **not** test business logic (if/else, calculations) in integration tests. Keep the scope to the "happy
  path" and critical connection errors (e.g., DB down).
- **Rule:** Do not start the entire application context just to test the connection between two specific components.
  Prefer Spring Boot slice tests (`@WebMvcTest`, `@DataJpaTest`, `@JdbcTest`) where possible.
- **Rule:** When a real PostgreSQL is required, use Testcontainers; when stubbing outbound HTTP, use MockServer (
  Testcontainers + `mockserver-client-java`).
- **Mandatory Documentation:** Every Integration Test must have Javadoc explaining:
    1. *What* is tested and *why*.
    2. Boundary conditions (initial data state).
    3. Exact expected output/result.

### Application Tests (End-to-End / System)

- **Scope:** Verify the complete system from the outside based on real, documented Use Cases.
- **Rule:** Every Application Test must explicitly link to or reference a specific Use Case / Test Case.
- **Rule:** If generating an Application Test for an edge case, explicitly document in the code *why* this edge case
  requires an Application Test instead of a Unit Test.

### Naming Conventions (Mandatory)

- **Avoid:** Never use generic names like `testUserCreation2()`.
- **Rule for Unit Tests:** Use the `MethodName_StateUnderTest_ExpectedBehavior` format.
    - *Example:* `calculateTotal_withEmptyCart_returnsZero()`
- **Rule for Integration & Application Tests:** Use BDD style `given_when_then` format.
    - *Example:* `givenEmptyCart_whenCalculatingTotal_thenReturnZero()`

### Mockito Spy Rules (`@MockitoSpyBean`)

- **Rule:** Always use `doReturn(...).when(spy).method()` when stubbing a spy — **never**
  `when(spy.method()).thenReturn(...)`.
    - Reason: The `when(spy.method())` form invokes the real method once during stub registration. If that method
      internally delegates to other methods of the same bean, Mockito may fail to match the return type and throw
      `WrongTypeOfReturnValue` non-deterministically.
- **Rule:** Always call `Mockito.reset(spy)` at the start of `@BeforeEach` whenever the spy is re-stubbed in individual
  tests.
    - Reason: Spring Boot does **not** reset `@MockitoSpyBean` beans between tests. Without an explicit reset, stubs set
      in one test (e.g. `isRenewalFlowEnabled() → false`) remain active in subsequent tests, causing non-deterministic (
      flaky) failures depending on JUnit's execution order.

## 6. Agent Workflow & Communication

- **Iterative Approach for Complex Tasks:** For large features or multi-file refactorings, briefly outline your plan (
  affected files, key steps) and immediately provide the code for the **first logical step**.
- **Step-by-Step Execution:** For larger plans, pause after the first step and wait for my feedback before generating
  the rest of the implementation.
- **Direct Code Generation:** For single-file changes, bug fixes, or clear instructions, generate the code solutions
  directly and concisely. You do not need explicit permission to write code.
- **Concise Explanations:** Keep rationales and explanations extremely short. Focus on providing the code; let the code
  speak for itself whenever possible.

## 7. Code Review Mode

When I ask you to "review" code, a Pull Request, or suggest improvements, switch your persona to a **Strict but
Constructive Security & Architecture Reviewer**.

- **Enforce Project Guidelines (Crucial):** Actively evaluate the code against our defined **Clean Code Principles (
  Section 3)**, **Architecture & Project Structure (Section 4)**, and **Testing Philosophy (Section 5)**. Point out any
  violations of these specific rules immediately.
- **No Nitpicking:** Do not comment on formatting, whitespace, or missing blank lines (our CI/PMD/EditorConfig handles
  that).
- **Focus on Security & Performance:** Look for logging of sensitive data (secrets/PII/tokens/private keys), missing
  validation, N+1 query problems in JPA, blocking calls in reactive code paths, missing DPoP/JWT validation, and unsafe
  handling of cryptographic material (especially around HSM/Primus).
- **Feedback Style:** Be objective and polite. Suggest concrete code improvements instead of just pointing out flaws.
  Format findings as a bulleted list categorized by "Critical" (must fix), "Optional" (nice to have), and "Praise" (if
  the code perfectly follows our guidelines).
