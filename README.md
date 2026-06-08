# Quarkus HTTP Message Signatures

[![Build Status](https://github.com/janhenke/quarkus-http-message-signatures/workflows/Quarkus%20Extension%20CI/badge.svg)](https://github.com<YOUR_GITHUB_ORG>/<YOUR_REPO_NAME>/actions)
[![Quarkus Version](https://img.shields.io/badge/Quarkus-3.33%2B-blue)](https://quarkus.io)

Quarkus extension to add [RFC 9421 (HTTP Message Signatures)](https://www.rfc-editor.org/info/rfc9421/) support, using [Authlete's Java implementation](https://github.com/authlete/http-message-signatures).

This extension enables your Quarkus applications to seamlessly generate, verify, and enforce end-to-end integrity and authenticity protections for HTTP requests and responses, fully supporting GraalVM native image compilation.

## 🚀 Features

*   **RFC 9421 Standard Compliant:** Full support for signature parameters, derived components (`@method`, `@target-uri`, `@authority`, `@status`), and custom covered field sets.
*   **Authlete Integration:** Leverages Authlete's highly reliable message signature parsing, serialization, and cryptographic primitives.
*   **Build-time Optimized:** Class scanning, configuration parsing, and reflection registration happen completely during the build phase.
*   **Native Ready:** Zero-configuration required to compile into ultra-fast GraalVM native binaries.

## 📦 Installation

To use this extension in your own Quarkus application, add the following dependency to your application's `pom.xml`:

```xml
<dependency>
    <groupId>io.github.janhenke</groupId>
    <artifactId>quarkus-http-message-signatures</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

## 🛠️ Configuration

Configure the extension inside your application's `src/main/resources/application.properties` file:

```properties
# Enable or disable the extension functionality globally
quarkus.http-signatures.enabled=true

# Mandate minimum components that must be covered by incoming signatures
quarkus.http-signatures.required-components=@method,@target-uri,@authority,date

# Specify permitted signature algorithms (e.g., rsa-pss-sha512, ecdsa-p256-sha256, ed25519)
quarkus.http-signatures.allowed-algorithms=rsa-pss-sha512,ecdsa-p256-sha256

# Authlete integration settings
quarkus.http-signatures.authlete.key-store-path=META-INF/resources/ke
```

## 🏗️ Project Structure

This project uses the standard Quarkus multi-module structure layout:

*   **`runtime/`**: Houses the runtime logic, config mappings, and `@Recorder` instructions deployed into the application.
*   **`deployment/`**: Houses the build steps (`@BuildStep`) that process code *exclusively* at build-time.
*   **`integration-tests/`**: A standalone Quarkus application module designed to verify functionality under real-world scenarios.

## 💻 Development & Contribution

### Prerequisites
*   Java 21 or higher
*   Apache Maven 3.9+
*   *(Optional)* GraalVM for native compilation

### Build & Install Locally
Compile the entire project hierarchy and store the extension in your local `~/.m2` cache repository:
```bash
mvn clean install
```

### Running the Integration Tests
The integration tests run automatically with the main install lifecycle, but you can target them individually:
```bash
mvn verify -f integration-tests/pom.xml
```

For native testing:
```bash
mvn verify -Pnative -f integration-tests/pom.xml
```

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
