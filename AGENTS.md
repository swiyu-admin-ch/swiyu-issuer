# AGENTS.md

## Project shape
- Maven multi-module (`swiyu-issuer-parent`): Java 25, Spring Boot 4.1.1. Build with `./mvnw`; CI uses Temurin 25.
- `issuer-service` = domain model, DTOs, business logic, repositories, shared config/utilities. HTTP controllers and
  app infrastructure live in `issuer-application`.
- `issuer-application` = Spring Boot entrypoint (`ch.admin.bj.swiyu.issuer.Application`) and web/infrastructure layer.
  It depends on `issuer-service`; never add the reverse dependency.
- Credential lifecycle transitions are driven by Spring Statemachine in `issuer-service`; do not bypass it by mutating
  offer or credential state directly from controllers or repositories.
- `.github/copilot-instructions.md` is the authoritative long-form rulebook (layering, naming, DI, testing, logging).
  Its pinned dependency versions can lag; treat `pom.xml` as the source of truth.

## Build & test
- Full gate: `./mvnw clean verify` — compiles, runs tests, JaCoCo, EditorConfig, and PMD. Integration tests need a
  Docker-compatible runtime because they use Testcontainers.
- Focused runs:
  - `./mvnw -pl issuer-service -Dtest=ClassNameTest test`
  - `./mvnw -pl issuer-application -am -Dtest=ClassNameIT -Dsurefire.failIfNoSpecifiedTests=false test`
    (`-am` is required when service code changed; the flag avoids "no tests" failures in upstream modules)
- `issuer-application` Surefire includes both `**/*Test.java` and `**/*IT.java`, so `mvn test` there starts
  PostgreSQL/MockServer containers; Docker must be running. `issuer-service` has unit and Pact consumer tests only.
- Integration tests use `@SpringBootTest @Testcontainers @ActiveProfiles("test")` with `PostgreSQLContainerInitializer`
  (shared from `issuer-service`'s test-jar). Changing shared test utilities affects both modules.
- PGP verification runs in `validate` and fails on missing/weak signatures. Public dependencies pass via the
  `*:*:* = any` catch-all; internal or unsigned ones need a rule in `pgp/keys.list` (`noSig` or pinned fingerprint).
  Inspect with `./mvnw pgpverify:show -Dartifact=g:a:v`; `-Dpgpverify.skip=true` is a local-only workaround.
- Pact: consumer tests are `*PactTest` in `issuer-service` (pacts in `target/pacts`). Provider tests live in
  `issuer-application/src/test/pact` and only compile/run with `-Ppact-provider`.

## API contract & codegen
- The root `openapi.yaml` is generated and committed; do not hand-edit it. After changing controllers or API DTOs run
  `./mvnw verify -P generate-doc -DskipTests` and commit the regenerated file. CI fails when it is stale.
- Doc generation starts the app on port 8080 with the `local` profile (Docker Compose PostgreSQL), so Docker and a
  free port 8080 are required.
- Compliance tests in `issuer-service/src/test/.../compliance/` load the committed root `openapi.yaml` and assert the
  Swiss Profile contract; requirement docs are in `.github/instructions/spez/`.
- External clients are generated from `issuer-service/specs/*.yaml` into `target/generated-sources`; edit the specs,
  never the generated code.

## Conventions & checks
- ArchUnit (`issuer-service` `ArchitectureTest`, `issuer-application` `RestControllerHaveIFTagArchTest`) enforces:
  - controllers `*Controller` in `..web..`; repositories `*Repository` in `..domain..`; entities in `..domain..`;
    mappers `*Mapper` as `@Service` in `..mapper..` (manual mapping; no MapStruct).
  - no field injection, no `java.util.logging`, no generic exceptions, no `*Interface` names; beans have final fields.
  - every `@RestController` needs a `@Tag` whose description contains a unique `(IF-123)` code.
  Some rules use `FreezingArchRule`: new violations fail instead of being silently accepted.
- Public classes, interfaces, and methods need English JavaDoc explaining intent; all comments/JavaDoc are English.
- Use `@Slf4j`; never log secrets, tokens, private keys, or PII.
- `.editorconfig` is checked at `verify`: LF, no trailing whitespace, and no final newline
  (`insert_final_newline = false`); it also specifies 4-space indents and 120 columns for editors.
- PMD uses `.github/rulesets/java/pmd_omni_ruleset.xml` and fails on priority <= 2 (bound to `verify`).
- Flyway loads both `issuer-application/src/main/resources/db/migration/common` and `.../postgres`. Hibernate runs
  `ddl-auto=validate`, so every entity/schema change needs a migration, not auto-DDL.
- Jackson 3 is the default (Spring Boot 4). `application.yml` sets `constructor-detector: use-properties-based` so
  Lombok `@Data`/`@Builder` DTOs deserialize; keep it unless you migrate the DTOs.

## Run locally
- `./mvnw -f issuer-application spring-boot:run -Dspring-boot.run.profiles=local` starts PostgreSQL 15 through
  `issuer-application/compose.yaml` (host port 5434) and applies Flyway migrations. Swagger UI:
  http://localhost:8080/swagger-ui/index.html.
- The app starts without status-registry credentials, but registry calls fail. Configuration and environment variables
  are documented in `README.md`.
- `Dockerfile.dhi` builds the default hardened image; `Dockerfile` builds the `-unhardened` UBI variant.

## Repo workflow
- Every commit must be DCO signed off with your real name: `git commit -s`.
- Dependency versions (many pinned for CVEs) live in the root `pom.xml`. Dependabot handles patch/minor; majors are
  manual.
- Keep `CHANGELOG.md` in Keep a Changelog format; unreleased user-facing changes go under `[NEXT]`.
- Existing AI workflows: `.github/instructions/make-release.instructions.md` (trigger "Start a Release"),
  `.github/instructions/review.instructions.md` ("Start Review"), and
  `.github/instructions/compliance-test.instructions.md` (Swiss Profile compliance tests).