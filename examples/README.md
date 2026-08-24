# Integrator Examples

This folder contains examples for extending the official `swiyu-issuer` Docker image.

---

## `Dockerfile.dhi.integrator` – Adding Custom CA Certificates

### When do you need this?

Use this example when your infrastructure terminates TLS with a **private or corporate CA** that is not trusted by default, e.g.:

- Corporate forward proxies performing TLS inspection
- Internal status registry or trust sidechannel endpoints
- On-premise HSM management interfaces

### How it works

The Dockerfile uses a two-stage build:

1. **Stage 1 (`cert-builder`):** Imports your `.crt` files into a copy of the Java trust store using `keytool`. A standard `eclipse-temurin:21-jre` image is used here because it has a shell and `keytool` available.
2. **Stage 2:** Extends the official `swiyu-issuer` image by injecting the prepared trust store into the exact path the JDK expects.

### Usage

1. Place your PEM-encoded CA certificates (`.crt`) in a local folder, e.g. `./my-certs/`.
2. Replace `swiyu-issuer:replace-with-official-tag` with the actual release tag.
3. Build the image:

```bash
docker build -f Dockerfile.dhi.integrator -t swiyu-issuer:my-org .
```

### Important notes

**`cacerts` path**

The path `/opt/java/openjdk/21-jre/lib/security/cacerts` is derived from `JAVA_HOME` in the base image. If the base image changes, verify the correct path with:

```bash
docker inspect <image> --format '{{range .Config.Env}}{{println .}}{{end}}' | grep JAVA_HOME
```

**OS trust store (optional)**

Some native TLS libraries (e.g. Netty OpenSSL) read the **Linux system trust store** instead of the Java one. If you need to update that as well, add a `debian:13-slim` stage that runs `update-ca-certificates` and inject the resulting `ca-certificates.crt`. See `Dockerfile.dhi` in the repository root for a complete example.

