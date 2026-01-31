# Examples

This directory contains examples demonstrating how to use the `jwks` library.

## Running Examples

To run any example, use:

```bash
cargo run --example <example_name>
```

## Available Examples

### `basic_usage.rs`

Demonstrates basic JWKS functionality:

- Fetching JWKS directly from a URL
- Fetching JWKS via OpenID Connect discovery

**Run with:**

```bash
cargo run --example basic_usage
```

### `jwt_validation.rs`

Shows how to use the library with `jsonwebtoken` for JWT validation:

- Extracting Key ID (kid) from JWT header
- Fetching JWKS from provider
- Finding matching key
- Validating JWT signature and claims

This example includes a mock JWT that uses Google's actual Key ID from their JWKS endpoint, demonstrating the complete validation workflow.

**Run with:**

```bash
cargo run --example jwt_validation
```

### `generate_jwt.rs`

Helper script to generate mock JWTs for testing:

- Creates JWTs with Google's actual Key ID
- Uses proper OAuth2 claim structure
- Includes timestamp-based expiration

**Run with:**

```bash
cargo run --example generate_jwt
```

## Network Requirements

Most examples require internet connectivity to fetch JWKS from external providers (like Google). If you see network errors, ensure you have an active internet connection.

**Note**: The library uses `rustls-tls` for HTTPS support, so no additional system TLS configuration is needed.

## Customization

Feel free to modify these examples for your specific use case:

- Change the JWKS URLs to match your provider
- Modify validation parameters
- Add custom claims structures
- Implement error handling specific to your application
