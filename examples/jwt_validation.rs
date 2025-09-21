//! JWT Validation Example
//!
//! This example demonstrates how to use the jwks library with jsonwebtoken
//! to validate JWT tokens using keys fetched from a JWKS endpoint.

use jsonwebtoken::{decode, decode_header, Validation};
use jwks::Jwks;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject identifier
    pub sub: String,
    /// Issuer (optional)
    pub iss: Option<String>,
    /// Audience (optional)
    pub aud: Option<String>,
    /// Expiration time (optional)
    pub exp: Option<u64>,
}

#[tokio::main]
async fn main() {
    println!("JWT Validation Example");
    println!("=====================\n");

    // In a real application, you would get this from an HTTP header
    // Example: Authorization: Bearer <jwt>
    let jwt = get_sample_jwt();

    if jwt.is_empty() {
        println!("No JWT provided for validation.");
        println!("To test this example:");
        println!("1. Get a real JWT from an OAuth2 provider (like Google, Auth0, etc.)");
        println!("2. Set it as the JWT string in the get_sample_jwt() function");
        println!("3. Make sure the JWKS URL matches your provider");
        return;
    }

    println!("🔍 Validating JWT...\n");

    // Step 1: Extract the Key ID (kid) from the JWT header
    let header = match decode_header(&jwt) {
        Ok(header) => {
            println!("✅ Successfully decoded JWT header");
            header
        }
        Err(e) => {
            println!("❌ Failed to decode JWT header: {}", e);
            return;
        }
    };

    let kid = match header.kid {
        Some(ref kid) => {
            println!("🔑 Found Key ID: {}", kid);
            kid
        }
        None => {
            println!("❌ JWT header does not contain a Key ID (kid)");
            return;
        }
    };

    // Step 2: Fetch JWKS from the provider
    println!("\n📡 Fetching JWKS from Google...");
    let jwks_url = "https://www.googleapis.com/oauth2/v3/certs";
    let jwks = match Jwks::from_jwks_url(jwks_url).await {
        Ok(jwks) => {
            println!("✅ Successfully fetched {} keys", jwks.keys.len());
            jwks
        }
        Err(e) => {
            println!("❌ Failed to fetch JWKS: {}", e);
            println!("Note: This example requires internet connectivity");
            return;
        }
    };

    // Step 3: Get the specific JWK for this JWT
    let jwk = match jwks.keys.get(kid) {
        Some(jwk) => {
            println!("✅ Found matching key for Key ID: {}", kid);
            jwk
        }
        None => {
            println!("❌ No matching key found for Key ID: {}", kid);
            println!("Available Key IDs:");
            for available_kid in jwks.keys.keys() {
                println!("  - {}", available_kid);
            }
            return;
        }
    };

    // Step 4: Validate the JWT
    println!("\n🔓 Decoding and validating JWT...");
    let mut validation = Validation::new(header.alg);

    // Set reasonable validation parameters
    validation.validate_exp = true;
    validation.validate_nbf = true;

    // You might want to set these based on your requirements
    // validation.set_issuer(&["https://accounts.google.com"]);
    // validation.set_audience(&["your-client-id"]);

    match decode::<Claims>(&jwt, &jwk.decoding_key, &validation) {
        Ok(token_data) => {
            println!("✅ JWT is valid!");
            println!("\n📋 Token Claims:");
            println!("  Subject (sub): {}", token_data.claims.sub);
            if let Some(iss) = &token_data.claims.iss {
                println!("  Issuer (iss): {}", iss);
            }
            if let Some(aud) = &token_data.claims.aud {
                println!("  Audience (aud): {:?}", aud);
            }
            if let Some(exp) = token_data.claims.exp {
                println!("  Expiration (exp): {}", exp);
            }
            println!("\n🔒 Header Algorithm: {:?}", token_data.header.alg);
        }
        Err(e) => {
            println!("❌ JWT validation failed: {}", e);
            println!("Common issues:");
            println!("  - JWT has expired");
            println!("  - JWT signature is invalid");
            println!("  - JWT issuer/audience doesn't match validation criteria");
        }
    }
}

/// Helper function to get a sample JWT for testing
/// Replace this with a real JWT from your OAuth2 provider
fn get_sample_jwt() -> String {
    // This is a placeholder. In a real application, you would:
    // 1. Get a JWT from an OAuth2 provider (Google, Auth0, etc.)
    // 2. Pass it via environment variable, config file, or command line argument
    // 3. Or get it from an HTTP request header

    "".to_string() // Return empty string for demo purposes
}