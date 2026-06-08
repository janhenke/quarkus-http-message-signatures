# RFC 9421 (HTTP Message Signatures) Quarkus Extension Implementation Plan

## Overview
The goal is to implement a Quarkus extension that provides support for RFC 9421 (HTTP Message Signatures) using the Authlete Java library. This extension will allow Quarkus applications to sign outgoing requests/responses and verify incoming signatures.

## 1. Technical Architecture

### 1.1 Core Library
- **Authlete http-message-signatures**: Used for parsing, serializing, and cryptographic operations.
- **Dependency**: `com.authlete:http-message-signatures`

### 1.2 Core Dependencies (Quarkus)
To avoid re-inventing key handling and security infrastructure, the extension will build upon:
- **`quarkus-security`**: Provides the base security APIs, `SecurityIdentity`, and `IdentityProvider`.
- **`quarkus-credentials`**: Provides the `CredentialsProvider` API for secure secret retrieval.
- **`quarkus-vertx-http`**: For integration with the Vert.x HTTP layer.

### 1.3 Configuration (`runtime`)
The extension will provide configuration properties to control its behavior, aligning with Quarkus conventions for security and HTTP. To maintain consistency and reduce implementation overhead, the configuration model for keys will follow patterns established by the `quarkus-oidc` and `quarkus-smallrye-jwt` extensions.

- `quarkus.http.signatures.enabled`: (Boolean) Enable/disable the extension.
- `quarkus.http.signatures.verify.enabled`: (Boolean) Enable verification of incoming requests.
- `quarkus.http.signatures.verify.policy`: (Enum) `PERMISSIVE` (verify if present), `ENFORCED` (fail if missing or invalid). Default: `ENFORCED`.
- `quarkus.http.signatures.verify.required-components`: (List of Strings) Components that must be present in the signature (e.g., `@method`, `@target-uri`, `date`).
- `quarkus.http.signatures.verify.allowed-algorithms`: (List of Strings) Permitted signature algorithms.
- `quarkus.http.signatures.verify.max-skew`: (Duration) Allowed clock skew for `created` parameter.
- `quarkus.http.signatures.sign.enabled`: (Boolean) Enable signing of outgoing messages.
- `quarkus.http.signatures.keys`: Key configuration for signing and verification.
    - `quarkus.http.signatures.keys.<id>.location`: Path or URL to the key (PEM, JWK, or JWKS).
    - `quarkus.http.signatures.keys.<id>.key-store-file`: (Optional) Path to KeyStore.
    - `quarkus.http.signatures.keys.<id>.password`: (Optional) Password for KeyStore or private key.
    - `quarkus.http.signatures.keys.<id>.secret-provider.key`: (Optional) Key for `CredentialsProvider` integration.
    - `quarkus.http.signatures.keys.<id>.type`: (Enum) `PEM`, `JWK`, `JWKS`, `KEYSTORE`.

### 1.3 Integration Points
- **Vert.x HTTP**: Use `HttpAuthenticationMechanism` for verifying incoming signatures and `HttpServerResponse` interceptors for signing outgoing responses. This ensures the extension works across all Quarkus web frameworks (RESTEasy Reactive, RESTEasy Classic, Reactive Routes).
- **Security Layer**: Integration with Quarkus Security (`SecurityIdentity`, `IdentityProvider`) to represent the verified signer as a principal.
- **Jakarta REST (JAX-RS)**: Use `ContainerRequestFilter` and `ContainerResponseFilter` as higher-level abstractions where appropriate, but prefer Vert.x for core logic.
- **REST Client**: Use `ClientRequestFilter` for signing outgoing requests in both REST Client and REST Client Reactive.

## 2. Implementation Modules

### 2.1 Runtime Module
- **Config**: Define `@ConfigRoot` and `@ConfigGroup` for the configuration properties.
- **Security Integration**:
    - `HttpMessageSignatureAuthenticationMechanism`: Implements `HttpAuthenticationMechanism` to verify signatures and establish `SecurityIdentity`.
    - `SignatureIdentityProvider`: Implements `IdentityProvider` to create a `SecurityIdentity` from a verified signature.
- **Filters/Handlers**:
    - `HttpMessageSignatureVerifyHandler` (Vert.x): Low-level verification if not using `HttpAuthenticationMechanism`.
    - `HttpMessageSignatureSignResponseFilter` (JAX-RS/Vert.x): Signs outgoing responses.
    - `HttpMessageSignatureClientFilter` (JAX-RS): Signs outgoing client requests.
- **Authlete Integration**:
    - Implement `SignatureContext` using Vert.x `RoutingContext` (server) and JAX-RS `ClientRequestContext` (client).
    - Provide `SignatureService` to encapsulate Authlete library calls.
- **Key Handling**:
    - Leverage Quarkus `KeyUtils` (from `quarkus-security`) and standard security configurations where possible.
    - Support loading public keys from JWKS URLs (similar to OIDC).
    - Support for `CredentialsProvider` (via `quarkus-credentials`) to handle key passwords and secrets securely.
    - Avoid deep coupling with `quarkus-oidc` to keep dependencies minimal, but mirror its configuration style for a better developer experience.

### 2.2 Deployment Module
- **Processors**:
    - `QuarkusHttpMessageSignaturesProcessor`:
        - Register Authlete library classes for reflection (needed for GraalVM).
        - Add `FeatureBuildItem`.
        - Register `HttpAuthenticationMechanism` via `ServiceStartBuildItem` or appropriate security build items.
        - Handle native image configuration (e.g., resource inclusion for keys).

### 2.3 Integration Tests
- **Test Scenarios**:
    - Basic GET/POST signature verification.
    - Test `PERMISSIVE` vs `ENFORCED` policies.
    - Missing required components (should fail in `ENFORCED`).
    - Expired signatures (should fail).
    - Algorithm mismatch (should fail).
    - Multi-signature handling.
    - Native image execution verification.

## 3. Phased Implementation Roadmap

The implementation is split into two logical phases to provide incremental value and manage complexity.

### Phase 1: Core Infrastructure & Server-side Verification (Inbound)
Focus on protecting Quarkus endpoints by verifying incoming signatures.

1.  **Dependency & Config**:
    - Set up Authlete dependency.
    - Implement `quarkus.http.signatures.verify.*` and `quarkus.http.signatures.keys` configuration.
2.  **Core Verification Logic**:
    - Implement `VertxSignatureContext` for `RoutingContext`.
    - Create `SignatureService` for verification.
    - Implement `KeyManager` for loading public keys.
3.  **Security Integration**:
    - Implement `HttpAuthenticationMechanism` to intercept and verify signatures.
    - Implement `SignatureIdentityProvider` to establish `SecurityIdentity`.
4.  **Deployment & Native**:
    - Register verification components.
    - Reflection registration for Authlete library.
5.  **Validation**:
    - Integration tests for verifying signed requests and rejecting invalid ones.

### Phase 2: Client-side & Response Signing (Outbound)
Focus on signing outgoing messages from the Quarkus application.

1.  **Signing Configuration**:
    - Enable `quarkus.http.signatures.sign.*`.
2.  **Core Signing Logic**:
    - Implement `JaxRsClientSignatureContext` for `ClientRequestContext`.
    - Update `SignatureService` and `KeyManager` to support private key signing.
3.  **Client Integration**:
    - Implement `HttpMessageSignatureClientFilter` for JAX-RS Client.
    - Implement client-side response verification (optional/advanced).
4.  **Response Signing (Optional/Advanced)**:
    - Implement `HttpMessageSignatureSignResponseFilter` for server responses.
5.  **Validation**:
    - End-to-end integration tests (Client signs -> Server verifies).

## 4. Documentation
- Update `README.md` with final configuration options and usage examples.
- Provide a guide on how to configure keys (KeyStore, PEM, etc.).
- Security guide for handling verified principals.
