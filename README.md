# jwks
Fetch and parse JSON Web Key Set (JWKS)

```
cargo add jwks
```

<https://crates.io/crates/jwks>

## Usage

### Basic Usage

From a jwks url:
```rust
let jwks_url = "https://www.googleapis.com/oauth2/v3/certs";
let jwks = Jwks::from_jwks_url(jwks_url).await.unwrap();
```

From a openid config url:
```rust
let openid_config_url = "https://accounts.google.com/.well-known/openid-configuration";
let jwks = Jwks::from_oidc_url(openid_config_url).await.unwrap();
```

### JWT Validation

For a complete example of using this library with [jsonwebtoken](https://github.com/Keats/jsonwebtoken) to validate JWTs, see the [examples/jwt_validation.rs](examples/jwt_validation.rs) file.

### Running Examples

You can run the examples with:

```bash
# Basic usage example
cargo run --example basic_usage

# JWT validation example
cargo run --example jwt_validation
```
