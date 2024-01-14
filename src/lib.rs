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
    use super::*;

    #[test]
    fn it_works() {}
}
