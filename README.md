# jwks

Fetch and parse JSON Web Key Set (JWKS)

```
cargo add jwks
```

<https://crates.io/crates/jwks>

### jsonwebtoken compatibility

`jwks` hands out [`jsonwebtoken`](https://github.com/Keats/jsonwebtoken) types (`DecodingKey`, `KeyAlgorithm`, errors), so your own `jsonwebtoken` dependency must be the same major version:

| jwks  | jsonwebtoken | MSRV |
|-------|--------------|------|
| 0.7.x | 12           | 1.88 |
| 0.6.x | 11           | 1.85 |

### Crypto backend

Enable exactly one backend. `rust_crypto` is the default; to use `aws_lc_rs`, turn the defaults off and add `http` back if you fetch with this crate:

```toml
jwks = { version = "0.7", default-features = false, features = ["aws_lc_rs", "http"] }
```

Enabling both makes `jsonwebtoken` panic at runtime when it picks a crypto provider.

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

Each usable key is in `jwks.keys`, indexed by `kid`:

```rust
let jwk = jwks.keys.get(kid).expect("unknown kid");
let token = jsonwebtoken::decode::<Claims>(token, &jwk.decoding_key, &validation)?;
```

### Unsupported keys

Keys that can't be used to verify signatures are skipped instead of failing the whole set: an unknown `kty` or curve, an unsupported `alg`, `use` other than `sig`, or `key_ops` without `verify`. They are listed in `jwks.unsupported` with a reason:

```rust
for key in &jwks.unsupported {
    eprintln!("skipped key {:?}: {}", key.kid, key.reason);
}
```

Keys with invalid values (bad base64, empty HMAC secret) still fail with `JwksError::KeyError`. A set with no usable key, including an empty one, fails with `JwksError::NoUsableKeys`.

### Without tokio

The `http` feature (on by default) fetches keys with an async `reqwest` client, which needs a tokio runtime. Turn it off to drop reqwest and tokio, fetch the JWKS with any client, and build the key set yourself:

```toml
jwks = { version = "0.7", default-features = false, features = ["rust_crypto"] }
```

```rust
let body = ureq::get("https://www.googleapis.com/oauth2/v3/certs")
    .call()?
    .into_body()
    .read_to_string()?;
let jwks = Jwks::from_json(&body)?;
```

`Jwks::from_jwk_set` and `Jwks::try_from(JwkSet)` do the same from an already parsed `jsonwebtoken::jwk::JwkSet`. These work with the `http` feature on too, for example to load keys from a file or cache.

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
