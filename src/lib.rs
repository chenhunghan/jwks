// Mostly edit from https://github.com/cdriehuys/axum-jwks/blob/main/axum-jwks/src/jwks.rs

use std::collections::HashMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{
    jwk::{self},
    DecodingKey,
};
use serde::Deserialize;
use thiserror::Error;
use tracing::debug;

/// A container for a set of JWT decoding keys.
///
/// The container can be used to validate any JWT that identifies a known key
/// through the `kid` attribute in the token's header.
#[derive(Clone)]
pub struct Jwks {
    keys: HashMap<String, Jwk>,
}

#[derive(Deserialize)]
struct OidcConfig {
    jwks_uri: String,
}

impl Jwks {
    /// # Arguments
    /// * `oidc_url` - The url with OpenID configuration, e.g. https://server.com/.well-known/openid-configuration
    pub async fn from_oidc_url(oidc_url: &str) -> Result<Self, JwksError> {
        Self::from_oidc_url_with_client(&reqwest::Client::default(), oidc_url).await
    }

    /// A version of [`from_oidc_url`][Self::from_oidc_url] that allows for
    /// passing in a custom [`Client`][reqwest::Client].
    pub async fn from_oidc_url_with_client(
        client: &reqwest::Client,
        oidc_url: &str,
    ) -> Result<Self, JwksError> {
        debug!(%oidc_url, "Fetching openid-configuration.");
        let oidc_config = client
            .get(oidc_url)
            .send()
            .await?
            .json::<OidcConfig>()
            .await?;
        let jwks_uri = oidc_config.jwks_uri;

        Self::from_jwks_url_with_client(&reqwest::Client::default(), &jwks_uri).await
    }

    /// # Arguments
    /// * `jwks_url` - The url which JWKS info is pulled from, e.g. https://example.com/.well-known/jwks.json
    pub async fn from_jwks_url(jwks_url: &str) -> Result<Self, JwksError> {
        Self::from_jwks_url_with_client(&reqwest::Client::default(), jwks_url).await
    }

    /// A version of [`from_jwks_url`][Self::from_jwks_url] that allows for
    /// passing in a custom [`Client`][reqwest::Client].
    pub async fn from_jwks_url_with_client(
        client: &reqwest::Client,
        jwks_url: &str,
    ) -> Result<Self, JwksError> {
        debug!(%jwks_url, "Fetching JSON Web Key Set.");
        let jwks: jwk::JwkSet = client.get(jwks_url).send().await?.json().await?;

        let mut keys = HashMap::new();
        for jwk in jwks.keys {
            let kid = jwk.common.key_id.ok_or(JwkError::MissingKeyId)?;

            match &jwk.algorithm {
                jwk::AlgorithmParameters::RSA(params) => {
                    let decoding_key = DecodingKey::from_rsa_components(&params.n, &params.e)
                        .map_err(|err| JwkError::DecodingError {
                            key_id: kid.clone(),
                            error: err,
                        })?;

                    keys.insert(
                        kid,
                        Jwk {
                            decoding_key: decoding_key,
                        },
                    );
                }
                jwk::AlgorithmParameters::EllipticCurve(params) => {
                    let decoding_key = DecodingKey::from_ec_components(&params.x, &params.y)
                        .map_err(|err| JwkError::DecodingError {
                            key_id: kid.clone(),
                            error: err,
                        })?;

                    keys.insert(
                        kid,
                        Jwk {
                            decoding_key: decoding_key,
                        },
                    );
                }
                jwk::AlgorithmParameters::OctetKeyPair(params) => {
                    let decoding_key =
                        DecodingKey::from_ed_components(&params.x).map_err(|err| {
                            JwkError::DecodingError {
                                key_id: kid.clone(),
                                error: err,
                            }
                        })?;

                    keys.insert(
                        kid,
                        Jwk {
                            decoding_key: decoding_key,
                        },
                    );
                }
                jwk::AlgorithmParameters::OctetKey(params) => {
                    // same as https://github.com/Keats/jsonwebtoken/blob/master/src/serialization.rs#L11
                    let base64_decoded = URL_SAFE_NO_PAD.decode(&params.value).map_err(|err| {
                        JwkError::DecodingError {
                            key_id: kid.clone(),
                            error: err.into(),
                        }
                    })?;
                    let decoding_key = DecodingKey::from_secret(&base64_decoded);
                    keys.insert(
                        kid,
                        Jwk {
                            decoding_key: decoding_key,
                        },
                    );
                }
            }
        }

        Ok(Self { keys })
    }
}

#[derive(Clone)]
struct Jwk {
    decoding_key: DecodingKey,
}

/// An error with the overall set of JSON Web Keys.
#[derive(Debug, Error)]
pub enum JwksError {
    /// There was an error fetching the OIDC or JWKS config from
    /// the specified url.
    #[error("could not fetch config from authority: {0}")]
    FetchError(#[from] reqwest::Error),

    /// An error with an individual key caused the processing of the JWKS to
    /// fail.
    #[error("there was an error with an individual key: {0}")]
    KeyError(#[from] JwkError),
}

/// An error with a specific key from a JWKS.
#[derive(Debug, Error)]
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
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[tokio::test]
    async fn can_fetch_and_parse_jwks() {
        let mut server = mockito::Server::new();

        let url = server.url();
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

        let _ = server
            .mock("GET", jwks_path)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(jwks.to_string())
            .create_async()
            .await;

        let jwks_url = format!("{}{}", url, jwks_path);
        let jwks = Jwks::from_jwks_url(&jwks_url).await.unwrap();
        assert_eq!(jwks.keys.len(), 2);
        
        // get keys by key id (kid)
        _ = &jwks.keys.get("91413cf4fa0cb92a3c3f5a054509132c47660937").expect("key one should be found");
        _ = &jwks.keys.get("1f40f0a8ef3d880978dc82f25c3ec317c6a5b781").expect("key two should be found");
    }
}
