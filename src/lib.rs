// Mostly edit from https://github.com/cdriehuys/axum-jwks/blob/main/axum-jwks/src/jwks.rs

//! Fetch and parse JSON Web Key Sets (JWKS).
//!
//! With the default `http` feature, `Jwks::from_jwks_url` and
//! `Jwks::from_oidc_url` fetch keys with an async `reqwest` client.
//! Without it, the crate does no I/O: fetch the JWKS with any client and
//! build a [`Jwks`] with [`Jwks::from_json`] or [`Jwks::from_jwk_set`].
//!
//! The [`jsonwebtoken`] version this crate is built against is re-exported,
//! so you can decode tokens with `jwks::jsonwebtoken` instead of keeping your
//! own `jsonwebtoken` dependency on a matching version.

use std::{collections::HashMap, str::FromStr};

pub use jsonwebtoken;

use jsonwebtoken::{
    jwk::{self, AlgorithmParameters, KeyAlgorithm, KeyOperations, PublicKeyUse},
    Algorithm, DecodingKey,
};
#[cfg(feature = "http")]
use serde::Deserialize;
use thiserror::Error;

/// A container for a set of JWT decoding keys.
///
/// The container can be used to validate any JWT that identifies a known key
/// through the `kid` attribute in the token's header.
#[derive(Clone)]
#[allow(dead_code)]
pub struct Jwks {
    pub keys: HashMap<String, Jwk>,
    /// Keys that were left out because they cannot be used for signature verification.
    pub unsupported: Vec<UnsupportedKey>,
}

#[cfg(feature = "http")]
#[derive(Deserialize)]
struct OIDCConfig {
    jwks_uri: String,
}

impl Jwks {
    /// Builds a [`Jwks`] from a JWKS JSON document, without any I/O.
    ///
    /// Keys that cannot be used for signature verification are skipped and
    /// listed in [`Jwks::unsupported`].
    ///
    /// ```
    /// let json = r#"{"keys": [{"kty": "oct", "alg": "HS256", "kid": "k1", "k": "c2VjcmV0"}]}"#;
    /// let jwks = jwks::Jwks::from_json(json).unwrap();
    /// assert!(jwks.keys.contains_key("k1"));
    /// ```
    pub fn from_json(json: &str) -> Result<Self, JwksError> {
        let jwk_set: jwk::JwkSet = serde_json::from_str(json)?;
        Self::from_jwk_set(&jwk_set)
    }

    /// Builds a [`Jwks`] from an already parsed [`JwkSet`][jwk::JwkSet], without any I/O.
    ///
    /// Keys that cannot be used for signature verification are skipped and
    /// listed in [`Jwks::unsupported`].
    pub fn from_jwk_set(jwk_set: &jwk::JwkSet) -> Result<Self, JwksError> {
        let mut keys = HashMap::new();
        let mut unsupported = Vec::new();
        for jwk in &jwk_set.keys {
            match JwkEntry::from_jsonwebkey_ref(jwk) {
                Ok(JwkEntry { kid, jwk }) => {
                    keys.insert(kid, jwk);
                }
                Err(JwkError::Unsupported(key)) => unsupported.push(key),
                Err(err) => return Err(err.into()),
            }
        }

        if keys.is_empty() {
            return Err(JwksError::NoUsableKeys { unsupported });
        }

        Ok(Self { keys, unsupported })
    }

    /// # Arguments
    /// * `oidc_url` - The url with OpenID configuration, e.g. https://accounts.google.com/.well-known/openid-configuration
    #[cfg(feature = "http")]
    pub async fn from_oidc_url(oidc_url: impl Into<String>) -> Result<Self, JwksError> {
        let url_str = oidc_url.into();
        Self::validate_url_scheme(&url_str)?;
        Self::from_oidc_url_with_client(&reqwest::Client::default(), url_str).await
    }

    /// A version of [`from_oidc_url`][Self::from_oidc_url] that allows for
    /// passing in a custom [`Client`][reqwest::Client].
    #[cfg(feature = "http")]
    pub async fn from_oidc_url_with_client(
        client: &reqwest::Client,
        oidc_url: impl Into<String>,
    ) -> Result<Self, JwksError> {
        let oidc_config = client
            .get(oidc_url.into())
            .send()
            .await?
            .json::<OIDCConfig>()
            .await?;
        let jwks_uri = oidc_config.jwks_uri;

        Self::from_jwks_url_with_client(client, &jwks_uri).await
    }

    /// # Arguments
    /// * `jwks_url` - The url which JWKS info is pulled from, e.g. https://www.googleapis.com/oauth2/v3/certs
    #[cfg(feature = "http")]
    pub async fn from_jwks_url(jwks_url: impl Into<String>) -> Result<Self, JwksError> {
        let url_str = jwks_url.into();
        Self::validate_url_scheme(&url_str)?;
        Self::from_jwks_url_with_client(&reqwest::Client::default(), url_str).await
    }

    /// A version of [`from_jwks_url`][Self::from_jwks_url] that allows for
    /// passing in a custom [`Client`][reqwest::Client].
    #[cfg(feature = "http")]
    pub async fn from_jwks_url_with_client(
        client: &reqwest::Client,
        jwks_url: impl Into<String>,
    ) -> Result<Self, JwksError> {
        let jwk_set: jwk::JwkSet = client.get(jwks_url.into()).send().await?.json().await?;
        Self::from_jwk_set(&jwk_set)
    }

    #[cfg(feature = "http")]
    fn validate_url_scheme(url: &str) -> Result<(), JwksError> {
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(JwksError::InvalidUrlScheme(url.to_string()));
        }
        Ok(())
    }
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct Jwk {
    /// The algorithm intended for use with this key.
    /// Per RFC 7517, this field is optional. When absent, the caller should
    /// determine the algorithm from another source (e.g., the JWT header's `alg` field).
    pub alg: Option<KeyAlgorithm>,
    pub decoding_key: DecodingKey,
}

#[allow(dead_code)]
pub struct JwkEntry {
    pub kid: String,
    pub jwk: Jwk,
}

impl JwkEntry {
    /// Converts a JWK into a decoding key entry.
    ///
    /// Returns [`JwkError::Unsupported`] for keys that cannot be used for
    /// signature verification, see [`UnsupportedReason`].
    pub fn from_jsonwebkey_ref(jwk: &jwk::Jwk) -> Result<Self, JwkError> {
        check_supported(jwk).map_err(|reason| {
            JwkError::Unsupported(UnsupportedKey {
                kid: jwk.common.key_id.clone(),
                reason,
            })
        })?;

        let kid = jwk.common.key_id.clone().ok_or(JwkError::MissingKeyId)?;

        let alg = jwk.common.key_algorithm;

        let decoding_key = DecodingKey::from_jwk(jwk).map_err(|err| JwkError::DecodingError {
            key_id: kid.clone(),
            error: err,
        })?;

        Ok(Self {
            kid,
            jwk: Jwk { alg, decoding_key },
        })
    }
}

/// Checks whether a key can be used for signature verification.
fn check_supported(jwk: &jwk::Jwk) -> Result<(), UnsupportedReason> {
    if let Some(key_use) = &jwk.common.public_key_use {
        if *key_use != PublicKeyUse::Signature {
            return Err(UnsupportedReason::Use(key_use.clone()));
        }
    }

    if let Some(key_ops) = &jwk.common.key_operations {
        if !key_ops.contains(&KeyOperations::Verify) {
            return Err(UnsupportedReason::KeyOps(key_ops.clone()));
        }
    }

    if let Some(alg) = jwk.common.key_algorithm {
        if Algorithm::from_str(&alg.to_string()).is_err() {
            return Err(UnsupportedReason::Algorithm(alg));
        }
    }

    match &jwk.algorithm {
        AlgorithmParameters::RSA(_)
        | AlgorithmParameters::EllipticCurve(_)
        | AlgorithmParameters::OctetKey(_)
        | AlgorithmParameters::OctetKeyPair(_) => Ok(()),
        AlgorithmParameters::Other(params) => Err(UnsupportedReason::UnknownKey {
            kty: params
                .fields
                .get("kty")
                .and_then(|v| v.as_str())
                .map(str::to_owned),
        }),
        _ => Err(UnsupportedReason::UnknownKey { kty: None }),
    }
}

impl TryFrom<jwk::JwkSet> for Jwks {
    type Error = JwksError;
    fn try_from(jwk_set: jwk::JwkSet) -> Result<Self, Self::Error> {
        Jwks::from_jwk_set(&jwk_set)
    }
}

impl TryFrom<jwk::Jwk> for JwkEntry {
    type Error = JwkError;
    fn try_from(j: jwk::Jwk) -> Result<Self, Self::Error> {
        JwkEntry::from_jsonwebkey_ref(&j)
    }
}

/// An error with the overall set of JSON Web Keys.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum JwksError {
    /// There was an error fetching the OIDC or JWKS config from
    /// the specified url.
    #[cfg(feature = "http")]
    #[error("could not fetch config from authority: {0}")]
    FetchError(#[from] reqwest::Error),

    /// The JWKS document is not valid JSON or not a JWK Set.
    #[error("could not parse the JWKS: {0}")]
    ParseError(#[from] serde_json::Error),

    /// An error with an individual key caused the processing of the JWKS to
    /// fail.
    #[error("there was an error with an individual key: {0}")]
    KeyError(#[from] JwkError),

    /// The URL is missing a required scheme (http:// or https://).
    #[cfg(feature = "http")]
    #[error("URL scheme is required - URL must start with http:// or https://. Got: {0}")]
    InvalidUrlScheme(String),

    /// The JWKS contains no key usable for signature verification.
    #[error("the JWKS contains no usable keys ({} unsupported)", unsupported.len())]
    NoUsableKeys { unsupported: Vec<UnsupportedKey> },
}

/// A key that cannot be used for signature verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedKey {
    pub kid: Option<String>,
    pub reason: UnsupportedReason,
}

/// Why a key cannot be used for signature verification.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum UnsupportedReason {
    /// Key parameters not recognized by jsonwebtoken: an unknown key type or
    /// curve, or a known key type with missing fields.
    #[error("unrecognized key parameters (kty: {kty:?})")]
    UnknownKey { kty: Option<String> },
    /// Algorithm (`alg`) is unknown or not a signature algorithm.
    #[error("unsupported algorithm {0}")]
    Algorithm(KeyAlgorithm),
    /// Key is not meant for signatures (`use`).
    #[error("key use is not \"sig\": {0:?}")]
    Use(PublicKeyUse),
    /// Key operations (`key_ops`) do not include `verify`.
    #[error("key operations do not include \"verify\": {0:?}")]
    KeyOps(Vec<KeyOperations>),
}

/// An error with a specific key from a JWKS.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum JwkError {
    /// There was an error constructing the decoding key from the RSA components
    /// provided by the key.
    #[error("could not construct a decoding key for {key_id:?}: {error:?}")]
    DecodingError {
        key_id: String,
        error: jsonwebtoken::errors::Error,
    },

    /// The key does not specify an algorithm to use.
    #[error("the key {key_id:?} does not specify an algorithm")]
    MissingAlgorithm { key_id: String },

    /// The key is missing the `kid` attribute.
    #[error("the key is missing the `kid` attribute")]
    MissingKeyId,

    /// The key cannot be used for signature verification.
    #[error(
        "the key {} is unsupported: {}",
        .0.kid.as_deref().unwrap_or("<no kid>"),
        .0.reason
    )]
    Unsupported(UnsupportedKey),
}

#[cfg(test)]
mod sync_tests {
    use super::*;

    const HMAC_KEY: &str =
        r#"{"kty": "oct", "alg": "HS256", "kid": "hmac", "k": "GawgguFyGrWKav7AX4VKUg"}"#;

    #[test]
    fn from_json_builds_keys_without_io() {
        let jwks = Jwks::from_json(&format!(r#"{{"keys": [{HMAC_KEY}]}}"#)).unwrap();
        assert!(jwks.keys.contains_key("hmac"));
        assert!(jwks.unsupported.is_empty());
    }

    #[test]
    fn from_json_skips_unsupported_keys() {
        let json =
            format!(r#"{{"keys": [{HMAC_KEY}, {{"kty": "AKP", "pub": "AAAA", "kid": "pq"}}]}}"#);
        let jwks = Jwks::from_json(&json).unwrap();
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.unsupported[0].kid.as_deref(), Some("pq"));
    }

    #[test]
    fn from_json_rejects_invalid_json() {
        assert!(matches!(
            Jwks::from_json("not json"),
            Err(JwksError::ParseError(_))
        ));
        assert!(matches!(
            Jwks::from_json(r#"{"no_keys": []}"#),
            Err(JwksError::ParseError(_))
        ));
    }

    #[test]
    fn from_json_rejects_set_without_usable_keys() {
        assert!(matches!(
            Jwks::from_json(r#"{"keys": []}"#),
            Err(JwksError::NoUsableKeys { .. })
        ));
    }

    #[test]
    fn try_from_jwk_set_matches_from_jwk_set() {
        let set: jwk::JwkSet =
            serde_json::from_str(&format!(r#"{{"keys": [{HMAC_KEY}]}}"#)).unwrap();
        let jwks = Jwks::try_from(set).unwrap();
        assert!(jwks.keys.contains_key("hmac"));
    }
}

#[cfg(all(test, feature = "http"))]
mod tests {
    use base64::engine::{general_purpose::URL_SAFE_NO_PAD, Engine};
    use serde_json::json;

    use super::*;
    use httpmock::prelude::*;

    #[tokio::test]
    async fn can_fetch_and_parse_jwks_from_jwks_url() {
        let server = MockServer::start();
        let jwks_path = "/oauth2/v3/certs";

        // from https://www.googleapis.com/oauth2/v3/certs
        let jwks = json!({
          "keys": [
            {
              "use": "sig",
              "n": "jb1Ps3fdt0oPYPbQlfZqKkCXrM1qJ5EkfBHSMrPXPzh9QLwa43WCLEdrTcf5vI8cNwbgSxDlCDS2BzHQC0hYPwFkJaD6y6NIIcwdSMcKlQPwk4-sqJbz55_gyUWjifcpXXKbXDdnd2QzSE2YipareOPJaBs3Ybuvf_EePnYoKEhXNeGm_T3546A56uOV2mNEe6e-RaIa76i8kcx_8JP3FjqxZSWRrmGYwZJhTGbeY5pfOS6v_EYpA4Up1kZANWReeC3mgh3O78f5nKEDxwPf99bIQ22fIC2779HbfzO-ybqR_EJ0zv8LlqfT7dMjZs25LH8Jw5wGWjP_9efP8emTOw",
              "kty": "RSA",
              "alg": "RS256",
              "e": "AQAB",
              "kid": "91413cf4fa0cb92a3c3f5a054509132c47660937"
            },
            {
              "n": "tgkwz0K80MycaI2Dz_jHkErJ_IHUPTlx4LR_6wltAHQW_ZwhMzINNH8vbWo8P5F2YLDiIbuslF9y7Q3izsPX3XWQyt6LI8ZT4gmGXQBumYMKx2VtbmTYIysKY8AY7x5UCDO-oaAcBuKQvWc5E31kXm6d6vfaEZjrMc_KT3DsFdN0LcAkB-Q9oYcVl7YEgAN849ROKUs6onf7eukj1PHwDzIBgA9AExJaKen0wITvxQv3H_BRXB7m6hFkLbK5Jo18gl3UxJ7Em29peEwi8Psn7MuI7CwhFNchKhjZM9eaMX27tpDPqR15-I6CA5Zf94rabUGWYph5cFXKWPPr8dskQQ",
              "alg": "RS256",
              "use": "sig",
              "kid": "1f40f0a8ef3d880978dc82f25c3ec317c6a5b781",
              "e": "AQAB",
              "kty": "RSA"
            }
          ]
        });

        let _ = server.mock(|when, then| {
            when.method(GET).path(jwks_path);
            then.status(200)
                .header("content-type", "application/json")
                .body(jwks.to_string());
        });

        let jwks_url = server.url(jwks_path);
        let jwks = Jwks::from_jwks_url(&jwks_url).await.unwrap();
        assert_eq!(jwks.keys.len(), 2);
        assert_eq!(
            jwks.keys
                .get("91413cf4fa0cb92a3c3f5a054509132c47660937")
                .unwrap()
                .alg,
            Some(KeyAlgorithm::RS256)
        );
        assert_eq!(
            jwks.keys
                .get("1f40f0a8ef3d880978dc82f25c3ec317c6a5b781")
                .unwrap()
                .alg,
            Some(KeyAlgorithm::RS256)
        );

        // get keys by key id (kid)
        _ = &jwks
            .keys
            .get("91413cf4fa0cb92a3c3f5a054509132c47660937")
            .expect("key one should be found");
        _ = &jwks
            .keys
            .get("1f40f0a8ef3d880978dc82f25c3ec317c6a5b781")
            .expect("key two should be found");
    }

    #[tokio::test]
    async fn can_fetch_and_parse_jwks_from_oidc_config_url() {
        let oidc_server = MockServer::start();

        let oidc_config_path = "/.well-known/openid-configuration";
        let jwks_path = "/oauth2/v3/certs";
        let jwks_url = oidc_server.url(jwks_path);

        // from https://accounts.google.com/.well-known/openid-configuration
        let oidc_config = json!({
         "issuer": "https://accounts.google.com",
         "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
         "device_authorization_endpoint": "https://oauth2.googleapis.com/device/code",
         "token_endpoint": "https://oauth2.googleapis.com/token",
         "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
         "revocation_endpoint": "https://oauth2.googleapis.com/revoke",
         "jwks_uri": jwks_url,
         "response_types_supported": [
          "code",
          "token",
          "id_token",
          "code token",
          "code id_token",
          "token id_token",
          "code token id_token",
          "none"
         ],
         "subject_types_supported": [
          "public"
         ],
         "id_token_signing_alg_values_supported": [
          "RS256"
         ],
         "scopes_supported": [
          "openid",
          "email",
          "profile"
         ],
         "token_endpoint_auth_methods_supported": [
          "client_secret_post",
          "client_secret_basic"
         ],
         "claims_supported": [
          "aud",
          "email",
          "email_verified",
          "exp",
          "family_name",
          "given_name",
          "iat",
          "iss",
          "locale",
          "name",
          "picture",
          "sub"
         ],
         "code_challenge_methods_supported": [
          "plain",
          "S256"
         ],
         "grant_types_supported": [
          "authorization_code",
          "refresh_token",
          "urn:ietf:params:oauth:grant-type:device_code",
          "urn:ietf:params:oauth:grant-type:jwt-bearer"
         ]
        });

        let _ = oidc_server.mock(|when, then| {
            when.method(GET).path(oidc_config_path);
            then.status(200)
                .header("content-type", "application/json")
                .body(oidc_config.to_string());
        });

        // from https://www.googleapis.com/oauth2/v3/certs
        let jwks = json!({
          "keys": [
            {
              "use": "sig",
              "n": "jb1Ps3fdt0oPYPbQlfZqKkCXrM1qJ5EkfBHSMrPXPzh9QLwa43WCLEdrTcf5vI8cNwbgSxDlCDS2BzHQC0hYPwFkJaD6y6NIIcwdSMcKlQPwk4-sqJbz55_gyUWjifcpXXKbXDdnd2QzSE2YipareOPJaBs3Ybuvf_EePnYoKEhXNeGm_T3546A56uOV2mNEe6e-RaIa76i8kcx_8JP3FjqxZSWRrmGYwZJhTGbeY5pfOS6v_EYpA4Up1kZANWReeC3mgh3O78f5nKEDxwPf99bIQ22fIC2779HbfzO-ybqR_EJ0zv8LlqfT7dMjZs25LH8Jw5wGWjP_9efP8emTOw",
              "kty": "RSA",
              "alg": "RS256",
              "e": "AQAB",
              "kid": "91413cf4fa0cb92a3c3f5a054509132c47660937"
            },
            {
              "n": "tgkwz0K80MycaI2Dz_jHkErJ_IHUPTlx4LR_6wltAHQW_ZwhMzINNH8vbWo8P5F2YLDiIbuslF9y7Q3izsPX3XWQyt6LI8ZT4gmGXQBumYMKx2VtbmTYIysKY8AY7x5UCDO-oaAcBuKQvWc5E31kXm6d6vfaEZjrMc_KT3DsFdN0LcAkB-Q9oYcVl7YEgAN849ROKUs6onf7eukj1PHwDzIBgA9AExJaKen0wITvxQv3H_BRXB7m6hFkLbK5Jo18gl3UxJ7Em29peEwi8Psn7MuI7CwhFNchKhjZM9eaMX27tpDPqR15-I6CA5Zf94rabUGWYph5cFXKWPPr8dskQQ",
              "alg": "RS256",
              "use": "sig",
              "kid": "1f40f0a8ef3d880978dc82f25c3ec317c6a5b781",
              "e": "AQAB",
              "kty": "RSA"
            }
          ]
        });

        let _ = oidc_server.mock(|when, then| {
            when.method(GET).path(jwks_path);
            then.status(200)
                .header("content-type", "application/json")
                .body(jwks.to_string());
        });

        let oidc_config_url = oidc_server.url(oidc_config_path);
        let jwks = Jwks::from_oidc_url(&oidc_config_url).await.unwrap();
        assert_eq!(jwks.keys.len(), 2);
        assert_eq!(
            jwks.keys
                .get("91413cf4fa0cb92a3c3f5a054509132c47660937")
                .unwrap()
                .alg,
            Some(KeyAlgorithm::RS256)
        );
        assert_eq!(
            jwks.keys
                .get("1f40f0a8ef3d880978dc82f25c3ec317c6a5b781")
                .unwrap()
                .alg,
            Some(KeyAlgorithm::RS256)
        );

        // get keys by key id (kid)
        _ = &jwks
            .keys
            .get("91413cf4fa0cb92a3c3f5a054509132c47660937")
            .expect("key one should be found");
        _ = &jwks
            .keys
            .get("1f40f0a8ef3d880978dc82f25c3ec317c6a5b781")
            .expect("key two should be found");
    }

    #[tokio::test]
    async fn handles_network_errors() {
        let jwks_url = "http://localhost:9999/nonexistent";
        let result = Jwks::from_jwks_url(jwks_url).await;
        assert!(matches!(result, Err(JwksError::FetchError(_))));
    }

    #[tokio::test]
    async fn handles_network_errors_with_custom_client() {
        let server = MockServer::start();
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(1))
            .build()
            .unwrap();

        let result = Jwks::from_jwks_url_with_client(&client, &server.url("/slow")).await;
        assert!(matches!(result, Err(JwksError::FetchError(_))));
    }

    #[tokio::test]
    async fn handles_invalid_json_response() {
        let server = MockServer::start();
        let _ = server.mock(|when, then| {
            when.method(GET).path("/invalid-json");
            then.status(200)
                .header("content-type", "application/json")
                .body("{ invalid json }");
        });

        let result = Jwks::from_jwks_url(&server.url("/invalid-json")).await;
        assert!(matches!(result, Err(JwksError::FetchError(_))));
    }

    #[tokio::test]
    async fn handles_non_json_response() {
        let server = MockServer::start();
        let _ = server.mock(|when, then| {
            when.method(GET).path("/text");
            then.status(200)
                .header("content-type", "text/plain")
                .body("not json");
        });

        let result = Jwks::from_jwks_url(&server.url("/text")).await;
        assert!(matches!(result, Err(JwksError::FetchError(_))));
    }

    #[tokio::test]
    async fn handles_http_error_response() {
        let server = MockServer::start();
        let _ = server.mock(|when, then| {
            when.method(GET).path("/error");
            then.status(404);
        });

        let result = Jwks::from_jwks_url(&server.url("/error")).await;
        assert!(matches!(result, Err(JwksError::FetchError(_))));
    }

    #[tokio::test]
    async fn handles_missing_keys_array() {
        let server = MockServer::start();
        let jwks = json!({
            "not_keys": []
        });

        let _ = server.mock(|when, then| {
            when.method(GET).path("/no-keys");
            then.status(200)
                .header("content-type", "application/json")
                .body(jwks.to_string());
        });

        let result = Jwks::from_jwks_url(&server.url("/no-keys")).await;
        assert!(matches!(result, Err(JwksError::FetchError(_))));
    }

    #[tokio::test]
    async fn handles_key_without_kid() {
        let server = MockServer::start();
        let jwks = json!({
            "keys": [{
                "kty": "RSA",
                "n": "jb1Ps3fdt0oPYPbQlfZqKkCXrM1qJ5EkfBHSMrPXPzh9QLwa43WCLEdrTcf5vI8cNwbgSxDlCDS2BzHQC0hYPwFkJaD6y6NIIcwdSMcKlQPwk4-sqJbz55_gyUWjifcpXXKbXDdnd2QzSE2YipareOPJaBs3Ybuvf_EePnYoKEhXNeGm_T3546A56uOV2mNEe6e-RaIa76i8kcx_8JP3FjqxZSWRrmGYwZJhTGbeY5pfOS6v_EYpA4Up1kZANWReeC3mgh3O78f5nKEDxwPf99bIQ22fIC2779HbfzO-ybqR_EJ0zv8LlqfT7dMjZs25LH8Jw5wGWjP_9efP8emTOw",
                "e": "AQAB",
                "alg": "RS256"
                // Missing kid
            }]
        });

        let _ = server.mock(|when, then| {
            when.method(GET).path("/no-kid");
            then.status(200)
                .header("content-type", "application/json")
                .body(jwks.to_string());
        });

        let result = Jwks::from_jwks_url(&server.url("/no-kid")).await;
        assert!(matches!(
            result,
            Err(JwksError::KeyError(JwkError::MissingKeyId))
        ));
    }

    #[tokio::test]
    async fn handles_key_without_algorithm() {
        let server = MockServer::start();
        let jwks = json!({
            "keys": [{
                "kty": "RSA",
                "n": "jb1Ps3fdt0oPYPbQlfZqKkCXrM1qJ5EkfBHSMrPXPzh9QLwa43WCLEdrTcf5vI8cNwbgSxDlCDS2BzHQC0hYPwFkJaD6y6NIIcwdSMcKlQPwk4-sqJbz55_gyUWjifcpXXKbXDdnd2QzSE2YipareOPJaBs3Ybuvf_EePnYoKEhXNeGm_T3546A56uOV2mNEe6e-RaIa76i8kcx_8JP3FjqxZSWRrmGYwZJhTGbeY5pfOS6v_EYpA4Up1kZANWReeC3mgh3O78f5nKEDxwPf99bIQ22fIC2779HbfzO-ybqR_EJ0zv8LlqfT7dMjZs25LH8Jw5wGWjP_9efP8emTOw",
                "e": "AQAB",
                "kid": "no-alg-key"
                // Missing alg - per RFC 7517, alg is optional
            }]
        });

        let _ = server.mock(|when, then| {
            when.method(GET).path("/no-alg");
            then.status(200)
                .header("content-type", "application/json")
                .body(jwks.to_string());
        });

        let jwks = Jwks::from_jwks_url(&server.url("/no-alg")).await.unwrap();
        assert_eq!(jwks.keys.len(), 1);
        let key = jwks.keys.get("no-alg-key").unwrap();
        assert_eq!(key.alg, None);
    }

    #[tokio::test]
    async fn handles_empty_jwks() {
        let server = MockServer::start();
        let jwks = json!({"keys": []});

        let _ = server.mock(|when, then| {
            when.method(GET).path("/empty");
            then.status(200)
                .header("content-type", "application/json")
                .body(jwks.to_string());
        });

        let result = Jwks::from_jwks_url(&server.url("/empty")).await;
        assert!(matches!(
            result,
            Err(JwksError::NoUsableKeys { unsupported }) if unsupported.is_empty()
        ));
    }

    #[tokio::test]
    async fn skips_unsupported_keys() {
        let server = MockServer::start();
        let jwks = json!({
            "keys": [
                {
                    "kty": "RSA",
                    "alg": "RS256",
                    "use": "sig",
                    "n": "jb1Ps3fdt0oPYPbQlfZqKkCXrM1qJ5EkfBHSMrPXPzh9QLwa43WCLEdrTcf5vI8cNwbgSxDlCDS2BzHQC0hYPwFkJaD6y6NIIcwdSMcKlQPwk4-sqJbz55_gyUWjifcpXXKbXDdnd2QzSE2YipareOPJaBs3Ybuvf_EePnYoKEhXNeGm_T3546A56uOV2mNEe6e-RaIa76i8kcx_8JP3FjqxZSWRrmGYwZJhTGbeY5pfOS6v_EYpA4Up1kZANWReeC3mgh3O78f5nKEDxwPf99bIQ22fIC2779HbfzO-ybqR_EJ0zv8LlqfT7dMjZs25LH8Jw5wGWjP_9efP8emTOw",
                    "e": "AQAB",
                    "kid": "rsa-sig"
                },
                {
                    "kty": "AKP",
                    "alg": "ML-DSA-44",
                    "pub": "AAAA",
                    "kid": "unknown-kty"
                },
                {
                    "kty": "OKP",
                    "crv": "Ed448",
                    "x": "AAAA",
                    "kid": "unknown-curve"
                },
                {
                    "kty": "RSA",
                    "use": "enc",
                    "n": "jb1Ps3fdt0oPYPbQlfZqKkCXrM1qJ5EkfBHSMrPXPzh9QLwa43WCLEdrTcf5vI8cNwbgSxDlCDS2BzHQC0hYPwFkJaD6y6NIIcwdSMcKlQPwk4-sqJbz55_gyUWjifcpXXKbXDdnd2QzSE2YipareOPJaBs3Ybuvf_EePnYoKEhXNeGm_T3546A56uOV2mNEe6e-RaIa76i8kcx_8JP3FjqxZSWRrmGYwZJhTGbeY5pfOS6v_EYpA4Up1kZANWReeC3mgh3O78f5nKEDxwPf99bIQ22fIC2779HbfzO-ybqR_EJ0zv8LlqfT7dMjZs25LH8Jw5wGWjP_9efP8emTOw",
                    "e": "AQAB",
                    "kid": "rsa-enc"
                },
                {
                    "kty": "RSA",
                    "alg": "RSA-OAEP",
                    "n": "jb1Ps3fdt0oPYPbQlfZqKkCXrM1qJ5EkfBHSMrPXPzh9QLwa43WCLEdrTcf5vI8cNwbgSxDlCDS2BzHQC0hYPwFkJaD6y6NIIcwdSMcKlQPwk4-sqJbz55_gyUWjifcpXXKbXDdnd2QzSE2YipareOPJaBs3Ybuvf_EePnYoKEhXNeGm_T3546A56uOV2mNEe6e-RaIa76i8kcx_8JP3FjqxZSWRrmGYwZJhTGbeY5pfOS6v_EYpA4Up1kZANWReeC3mgh3O78f5nKEDxwPf99bIQ22fIC2779HbfzO-ybqR_EJ0zv8LlqfT7dMjZs25LH8Jw5wGWjP_9efP8emTOw",
                    "e": "AQAB"
                    // No kid: unsupported keys may omit it
                }
            ]
        });

        let _ = server.mock(|when, then| {
            when.method(GET).path("/unsupported");
            then.status(200)
                .header("content-type", "application/json")
                .body(jwks.to_string());
        });

        let jwks = Jwks::from_jwks_url(&server.url("/unsupported"))
            .await
            .unwrap();
        assert_eq!(jwks.keys.len(), 1);
        assert!(jwks.keys.contains_key("rsa-sig"));

        let unsupported: Vec<_> = jwks
            .unsupported
            .iter()
            .map(|k| (k.kid.as_deref(), k.reason.clone()))
            .collect();
        assert_eq!(
            unsupported,
            vec![
                (
                    Some("unknown-kty"),
                    UnsupportedReason::Algorithm(KeyAlgorithm::UNKNOWN_ALGORITHM)
                ),
                (
                    Some("unknown-curve"),
                    UnsupportedReason::UnknownKey {
                        kty: Some("OKP".to_owned())
                    }
                ),
                (
                    Some("rsa-enc"),
                    UnsupportedReason::Use(PublicKeyUse::Encryption)
                ),
                (None, UnsupportedReason::Algorithm(KeyAlgorithm::RSA_OAEP)),
            ]
        );
    }

    #[tokio::test]
    async fn skips_unknown_key_type_without_alg() {
        let server = MockServer::start();
        let jwks = json!({
            "keys": [
                {
                    "kty": "oct",
                    "alg": "HS256",
                    "k": "GawgguFyGrWKav7AX4VKUg",
                    "kid": "hmac"
                },
                {
                    "kty": "AKP",
                    "pub": "AAAA",
                    "kid": "unknown-kty"
                }
            ]
        });

        let _ = server.mock(|when, then| {
            when.method(GET).path("/unknown-kty");
            then.status(200)
                .header("content-type", "application/json")
                .body(jwks.to_string());
        });

        let jwks = Jwks::from_jwks_url(&server.url("/unknown-kty"))
            .await
            .unwrap();
        assert!(jwks.keys.contains_key("hmac"));
        assert_eq!(
            jwks.unsupported,
            vec![UnsupportedKey {
                kid: Some("unknown-kty".to_owned()),
                reason: UnsupportedReason::UnknownKey {
                    kty: Some("AKP".to_owned())
                },
            }]
        );
    }

    #[tokio::test]
    async fn skips_keys_without_verify_key_op() {
        let server = MockServer::start();
        let jwks = json!({
            "keys": [
                {
                    "kty": "oct",
                    "alg": "HS256",
                    "key_ops": ["sign", "verify"],
                    "k": "GawgguFyGrWKav7AX4VKUg",
                    "kid": "verify"
                },
                {
                    "kty": "oct",
                    "alg": "HS256",
                    "key_ops": ["encrypt"],
                    "k": "GawgguFyGrWKav7AX4VKUg",
                    "kid": "encrypt"
                }
            ]
        });

        let _ = server.mock(|when, then| {
            when.method(GET).path("/key-ops");
            then.status(200)
                .header("content-type", "application/json")
                .body(jwks.to_string());
        });

        let jwks = Jwks::from_jwks_url(&server.url("/key-ops")).await.unwrap();
        assert!(jwks.keys.contains_key("verify"));
        assert_eq!(
            jwks.unsupported,
            vec![UnsupportedKey {
                kid: Some("encrypt".to_owned()),
                reason: UnsupportedReason::KeyOps(vec![KeyOperations::Encrypt]),
            }]
        );
    }

    #[test]
    fn unsupported_error_message_formats_kid() {
        let err = |kid: Option<&str>| {
            JwkError::Unsupported(UnsupportedKey {
                kid: kid.map(str::to_owned),
                reason: UnsupportedReason::Use(PublicKeyUse::Encryption),
            })
            .to_string()
        };
        assert!(err(Some("abc")).starts_with("the key abc is unsupported"));
        assert!(err(None).starts_with("the key <no kid> is unsupported"));
    }

    #[tokio::test]
    async fn rejects_jwks_with_only_unsupported_keys() {
        let server = MockServer::start();
        let jwks = json!({
            "keys": [{
                "kty": "AKP",
                "pub": "AAAA",
                "kid": "unknown-kty"
            }]
        });

        let _ = server.mock(|when, then| {
            when.method(GET).path("/only-unsupported");
            then.status(200)
                .header("content-type", "application/json")
                .body(jwks.to_string());
        });

        let result = Jwks::from_jwks_url(&server.url("/only-unsupported")).await;
        assert!(matches!(
            result,
            Err(JwksError::NoUsableKeys { unsupported }) if unsupported.len() == 1
        ));
    }

    #[tokio::test]
    async fn rejects_empty_hmac_key() {
        let server = MockServer::start();
        let jwks = json!({
            "keys": [
                {
                    "kty": "oct",
                    "alg": "HS256",
                    "k": "GawgguFyGrWKav7AX4VKUg",
                    "kid": "hmac"
                },
                {
                    "kty": "oct",
                    "alg": "HS256",
                    "k": "",
                    "kid": "empty-hmac"
                }
            ]
        });

        let _ = server.mock(|when, then| {
            when.method(GET).path("/empty-hmac");
            then.status(200)
                .header("content-type", "application/json")
                .body(jwks.to_string());
        });

        let result = Jwks::from_jwks_url(&server.url("/empty-hmac")).await;
        assert!(matches!(
            result,
            Err(JwksError::KeyError(JwkError::DecodingError { key_id, .. })) if key_id == "empty-hmac"
        ));
    }

    #[tokio::test]
    async fn handles_oidc_network_error() {
        let server = MockServer::start();
        let result = Jwks::from_oidc_url(&server.url("/nonexistent")).await;
        assert!(matches!(result, Err(JwksError::FetchError(_))));
    }

    #[tokio::test]
    async fn handles_invalid_oidc_config() {
        let server = MockServer::start();
        let invalid_config = json!({
            "invalid_field": "invalid_value"
        });

        let _ = server.mock(|when, then| {
            when.method(GET).path("/invalid-oidc");
            then.status(200)
                .header("content-type", "application/json")
                .body(invalid_config.to_string());
        });

        let result = Jwks::from_oidc_url(&server.url("/invalid-oidc")).await;
        assert!(matches!(result, Err(JwksError::FetchError(_))));
    }

    #[tokio::test]
    async fn handles_url_without_scheme() {
        let result = Jwks::from_jwks_url("example.com/.well-known/jwks.json").await;
        assert!(matches!(result, Err(JwksError::InvalidUrlScheme(_))));
    }

    #[tokio::test]
    async fn handles_oidc_url_without_scheme() {
        let result =
            Jwks::from_oidc_url("accounts.google.com/.well-known/openid-configuration").await;
        assert!(matches!(result, Err(JwksError::InvalidUrlScheme(_))));
    }

    #[tokio::test]
    async fn can_parse_ec_keys_with_ec_p256_algorithms() {
        let server = MockServer::start();
        let jwks_path = "/ec-keys";

        let jwks = json!({
          "keys": [
            {
              "use": "sig",
              "kty": "EC",
              "alg": "ES256",
              "crv": "P-256",
              "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
              "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
              "kid": "ec-p256-key"
            }
          ]
        });

        let _ = server.mock(|when, then| {
            when.method(GET).path(jwks_path);
            then.status(200)
                .header("content-type", "application/json")
                .body(jwks.to_string());
        });

        let jwks = Jwks::from_jwks_url(&server.url(jwks_path)).await.unwrap();
        assert_eq!(jwks.keys.len(), 1);

        // Test P-256 key
        let p256_key = jwks.keys.get("ec-p256-key").unwrap();
        assert_eq!(p256_key.alg, Some(KeyAlgorithm::ES256));
    }

    #[tokio::test]
    async fn handles_ec_key_missing_coordinates() {
        let server = MockServer::start();
        let jwks_path = "/ec-missing-coords";

        let jwks = json!({
          "keys": [
            {
              "use": "sig",
              "kty": "EC",
              "alg": "ES256",
              "crv": "P-256",
              "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
              // Missing y coordinate
              "kid": "ec-missing-y"
            }
          ]
        });

        let _ = server.mock(|when, then| {
            when.method(GET).path(jwks_path);
            then.status(200)
                .header("content-type", "application/json")
                .body(jwks.to_string());
        });

        let result = Jwks::from_jwks_url(&server.url(jwks_path)).await;
        assert!(matches!(
            result,
            Err(JwksError::NoUsableKeys { unsupported }) if unsupported == vec![UnsupportedKey {
                kid: Some("ec-missing-y".to_owned()),
                reason: UnsupportedReason::UnknownKey { kty: Some("EC".to_owned()) },
            }]
        ));
    }

    #[tokio::test]
    async fn handles_ec_key_invalid_coordinates() {
        let server = MockServer::start();
        let jwks_path = "/ec-invalid-coords";

        let jwks = json!({
          "keys": [
            {
              "use": "sig",
              "kty": "EC",
              "alg": "ES256",
              "crv": "P-256",
              "x": "invalid_base64!",
              "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
              "kid": "ec-invalid-x"
            }
          ]
        });

        let _ = server.mock(|when, then| {
            when.method(GET).path(jwks_path);
            then.status(200)
                .header("content-type", "application/json")
                .body(jwks.to_string());
        });

        let result = Jwks::from_jwks_url(&server.url(jwks_path)).await;
        assert!(matches!(
            result,
            Err(JwksError::KeyError(JwkError::DecodingError { .. }))
        ));
    }

    #[tokio::test]
    async fn handles_ec_key_missing_curve() {
        let server = MockServer::start();
        let jwks_path = "/ec-missing-curve";

        let jwks = json!({
          "keys": [
            {
              "use": "sig",
              "kty": "EC",
              "alg": "ES256",
              // Missing crv parameter
              "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
              "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
              "kid": "ec-missing-curve"
            }
          ]
        });

        let _ = server.mock(|when, then| {
            when.method(GET).path(jwks_path);
            then.status(200)
                .header("content-type", "application/json")
                .body(jwks.to_string());
        });

        let result = Jwks::from_jwks_url(&server.url(jwks_path)).await;
        assert!(matches!(
            result,
            Err(JwksError::NoUsableKeys { unsupported }) if unsupported == vec![UnsupportedKey {
                kid: Some("ec-missing-curve".to_owned()),
                reason: UnsupportedReason::UnknownKey { kty: Some("EC".to_owned()) },
            }]
        ));
    }

    #[tokio::test]
    async fn can_parse_mixed_key_types() {
        let server = MockServer::start();
        let jwks_path = "/mixed-keys";

        let jwks = json!({
          "keys": [
            {
              "use": "sig",
              "n": "jb1Ps3fdt0oPYPbQlfZqKkCXrM1qJ5EkfBHSMrPXPzh9QLwa43WCLEdrTcf5vI8cNwbgSxDlCDS2BzHQC0hYPwFkJaD6y6NIIcwdSMcKlQPwk4-sqJbz55_gyUWjifcpXXKbXDdnd2QzSE2YipareOPJaBs3Ybuvf_EePnYoKEhXNeGm_T3546A56uOV2mNEe6e-RaIa76i8kcx_8JP3FjqxZSWRrmGYwZJhTGbeY5pfOS6v_EYpA4Up1kZANWReeC3mgh3O78f5nKEDxwPf99bIQ22fIC2779HbfzO-ybqR_EJ0zv8LlqfT7dMjZs25LH8Jw5wGWjP_9efP8emTOw",
              "kty": "RSA",
              "alg": "RS256",
              "e": "AQAB",
              "kid": "rsa-key"
            },
            {
              "use": "sig",
              "kty": "EC",
              "alg": "ES256",
              "crv": "P-256",
              "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
              "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
              "kid": "ec-key"
            },
            {
              "use": "sig",
              "kty": "oct",
              "alg": "HS256",
              "k": "GawgguFyGrWKav7AX4VKUg",
              "kid": "symmetric-key"
            }
          ]
        });

        let _ = server.mock(|when, then| {
            when.method(GET).path(jwks_path);
            then.status(200)
                .header("content-type", "application/json")
                .body(jwks.to_string());
        });

        let jwks = Jwks::from_jwks_url(&server.url(jwks_path)).await.unwrap();
        assert_eq!(jwks.keys.len(), 3);

        // Test RSA key
        let rsa_key = jwks.keys.get("rsa-key").unwrap();
        assert_eq!(rsa_key.alg, Some(KeyAlgorithm::RS256));

        // Test EC key
        let ec_key = jwks.keys.get("ec-key").unwrap();
        assert_eq!(ec_key.alg, Some(KeyAlgorithm::ES256));

        // Test symmetric key
        let symmetric_key = jwks.keys.get("symmetric-key").unwrap();
        assert_eq!(symmetric_key.alg, Some(KeyAlgorithm::HS256));
    }

    #[tokio::test]
    async fn e2e_jwt_sign_and_verify_with_rsa_key() {
        use jsonwebtoken::{decode, encode, EncodingKey, Header, Validation};
        use rsa::pkcs1::EncodeRsaPrivateKey;
        use rsa::traits::PublicKeyParts;
        use serde_json::json;

        let server = MockServer::start();
        let jwks_path = "/jwks";

        // Generate RSA key pair for the test
        let mut rng = rand::rng();
        let private_key = rsa::PrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = private_key.to_public_key();

        // Extract components for JWKS
        let n = URL_SAFE_NO_PAD.encode(public_key.n_bytes());
        let e = URL_SAFE_NO_PAD.encode(public_key.e_bytes());

        // Create JWKS with the public key
        let jwks_data = json!({
          "keys": [
            {
              "use": "sig",
              "n": n,
              "kty": "RSA",
              "alg": "RS256",
              "e": e,
              "kid": "test-rsa-key"
            }
          ]
        });

        let _ = server.mock(|when, then| {
            when.method(GET).path(jwks_path);
            then.status(200)
                .header("content-type", "application/json")
                .body(jwks_data.to_string());
        });

        // Fetch JWKS using the library
        let jwks_url = server.url(jwks_path);
        let jwks = Jwks::from_jwks_url(&jwks_url).await.unwrap();

        // Create JWT claims (with future expiration)
        let now = jsonwebtoken::get_current_timestamp();
        let claims = json!({
            "sub": "1234567890",
            "name": "John Doe",
            "iat": now,
            "exp": now + 3600
        });

        // Sign JWT with private key
        let header = Header::new(jsonwebtoken::Algorithm::RS256);
        let encoding_key =
            EncodingKey::from_rsa_der(&private_key.to_pkcs1_der().unwrap().to_bytes());
        let token = encode(&header, &claims, &encoding_key).unwrap();

        // Verify JWT using the fetched JWKS
        let test_key = jwks.keys.get("test-rsa-key").unwrap();
        let validation = Validation::new(jsonwebtoken::Algorithm::RS256);
        let token_data =
            decode::<serde_json::Value>(&token, &test_key.decoding_key, &validation).unwrap();

        // Verify the claims
        assert_eq!(token_data.claims, claims);
        assert_eq!(token_data.header.alg, jsonwebtoken::Algorithm::RS256);
    }

    // Note: EC key test is omitted for brevity, but would follow similar pattern
    // with proper key generation and conversion between public/private key formats

    #[tokio::test]
    async fn e2e_jwt_sign_and_verify_with_symmetric_key() {
        use jsonwebtoken::{decode, encode, EncodingKey, Header, Validation};
        use serde_json::json;

        let server = MockServer::start();
        let jwks_path = "/jwks";

        // Generate symmetric key for the test
        let symmetric_key = b"my-super-secret-symmetric-key";
        let encoded_key = URL_SAFE_NO_PAD.encode(symmetric_key);

        // Create JWKS with the symmetric key
        let jwks_data = json!({
          "keys": [
            {
              "use": "sig",
              "kty": "oct",
              "alg": "HS256",
              "k": encoded_key,
              "kid": "test-symmetric-key"
            }
          ]
        });

        let _ = server.mock(|when, then| {
            when.method(GET).path(jwks_path);
            then.status(200)
                .header("content-type", "application/json")
                .body(jwks_data.to_string());
        });

        // Fetch JWKS using the library
        let jwks_url = server.url(jwks_path);
        let jwks = Jwks::from_jwks_url(&jwks_url).await.unwrap();

        // Create JWT claims (with future expiration)
        let now = jsonwebtoken::get_current_timestamp();
        let claims = json!({
            "sub": "1234567890",
            "name": "Alice Smith",
            "iat": now,
            "exp": now + 3600
        });

        // Sign JWT with symmetric key
        let header = Header::new(jsonwebtoken::Algorithm::HS256);
        let encoding_key = EncodingKey::from_secret(symmetric_key).unwrap();
        let token = encode(&header, &claims, &encoding_key).unwrap();

        // Verify JWT using the fetched JWKS
        let test_key = jwks.keys.get("test-symmetric-key").unwrap();
        let validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        let token_data =
            decode::<serde_json::Value>(&token, &test_key.decoding_key, &validation).unwrap();

        // Verify the claims
        assert_eq!(token_data.claims, claims);
        assert_eq!(token_data.header.alg, jsonwebtoken::Algorithm::HS256);
    }

    #[tokio::test]
    async fn e2e_jwt_verify_with_oidc_discovery() {
        use jsonwebtoken::{decode, encode, EncodingKey, Header, Validation};
        use rsa::pkcs1::EncodeRsaPrivateKey;
        use rsa::traits::PublicKeyParts;

        let oidc_server = MockServer::start();

        let oidc_config_path = "/.well-known/openid-configuration";
        let jwks_path = "/oauth2/v3/certs";
        let jwks_url = oidc_server.url(jwks_path);

        // Generate RSA key pair for the test
        let mut rng = rand::rng();
        let private_key = rsa::PrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = private_key.to_public_key();

        // Extract components for JWKS
        let n = URL_SAFE_NO_PAD.encode(public_key.n_bytes());
        let e = URL_SAFE_NO_PAD.encode(public_key.e_bytes());

        // Create OIDC configuration
        let oidc_config = json!({
         "issuer": "https://auth.example.com",
         "authorization_endpoint": "https://auth.example.com/oauth2/v2/auth",
         "token_endpoint": "https://auth.example.com/oauth2/v2/token",
         "jwks_uri": jwks_url,
         "response_types_supported": ["code"],
         "subject_types_supported": ["public"],
         "id_token_signing_alg_values_supported": ["RS256"],
         "scopes_supported": ["openid", "email", "profile"]
        });

        let _ = oidc_server.mock(|when, then| {
            when.method(GET).path(oidc_config_path);
            then.status(200)
                .header("content-type", "application/json")
                .body(oidc_config.to_string());
        });

        // Create JWKS with the public key
        let jwks_data = json!({
          "keys": [
            {
              "use": "sig",
              "n": n,
              "kty": "RSA",
              "alg": "RS256",
              "e": e,
              "kid": "test-oidc-key"
            }
          ]
        });

        let _ = oidc_server.mock(|when, then| {
            when.method(GET).path(jwks_path);
            then.status(200)
                .header("content-type", "application/json")
                .body(jwks_data.to_string());
        });

        // Fetch JWKS using OIDC discovery
        let oidc_config_url = oidc_server.url(oidc_config_path);
        let jwks = Jwks::from_oidc_url(&oidc_config_url).await.unwrap();

        // Create JWT claims (with future expiration)
        let now = jsonwebtoken::get_current_timestamp();
        let claims = json!({
            "sub": "1234567890",
            "name": "Bob Johnson",
            "iat": now,
            "exp": now + 3600,
            "iss": "https://auth.example.com"
        });

        // Sign JWT with private key
        let header = Header::new(jsonwebtoken::Algorithm::RS256);
        let encoding_key =
            EncodingKey::from_rsa_der(&private_key.to_pkcs1_der().unwrap().to_bytes());
        let token = encode(&header, &claims, &encoding_key).unwrap();

        // Verify JWT using the fetched JWKS
        let test_key = jwks.keys.get("test-oidc-key").unwrap();
        let mut validation = Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_issuer(&["https://auth.example.com"]);
        let token_data =
            decode::<serde_json::Value>(&token, &test_key.decoding_key, &validation).unwrap();

        // Verify the claims
        assert_eq!(token_data.claims, claims);
        assert_eq!(token_data.header.alg, jsonwebtoken::Algorithm::RS256);
    }
}
