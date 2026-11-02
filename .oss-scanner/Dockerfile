FROM maven:3.9-eclipse-temurin-25
ENV DEBIAN_FRONTEND=noninteractive \
    MAVEN_OPTS="-Xmx2g"
RUN apt-get update && apt-get install -y --no-install-recommends \
      git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# Build all modules and install them into ~/.m2 (network is available during this step only).
# This also fills the PGP key cache used by pgpverify-maven-plugin (~/.m2/repository/pgpkeys-cache).
RUN mvn --batch-mode -DskipTests install

# Run the tests so that all test/surefire dependencies are cached for the offline phase.
# A failing test must not abort the build. Note: the *IT tests use Testcontainers (PostgreSQL, MockServer,
# Keycloak) and need a Docker daemon, which is not available during the image build; they fail here
# and are ignored. -Dmaven.test.failure.ignore lets every module resolve its test dependencies.
RUN mvn --batch-mode -Dmaven.test.failure.ignore=true verify || echo "WARNING: tests reported failures"
