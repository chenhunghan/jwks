//! Basic Usage Examples
//!
//! This example demonstrates the basic functionality of the jwks library:
//! - Fetching JWKS directly from a URL
//! - Fetching JWKS via OpenID Connect discovery

use jwks::Jwks;

#[tokio::main]
async fn main() {
    println!("JWKS Library Examples");
    println!("====================");

    // Example 1: Fetch JWKS from a URL
    println!("\n1. Fetching JWKS from URL...");
    let jwks_url = "https://www.googleapis.com/oauth2/v3/certs";
    match Jwks::from_jwks_url(jwks_url).await {
        Ok(jwks) => {
            println!("✅ Successfully fetched {} keys from JWKS", jwks.keys.len());
            for (kid, jwk) in &jwks.keys {
                println!("  - Key ID: {}, Algorithm: {:?}", kid, jwk.alg);
            }
        }
        Err(e) => {
            println!("❌ Error fetching JWKS: {}", e);
            println!("   Note: This example requires internet connectivity to fetch Google's JWKS");
        }
    }

    // Example 2: Fetch JWKS from OpenID configuration
    println!("\n2. Fetching JWKS from OpenID configuration...");
    let openid_config_url = "https://accounts.google.com/.well-known/openid-configuration";
    match Jwks::from_oidc_url(openid_config_url).await {
        Ok(jwks) => {
            println!(
                "✅ Successfully fetched {} keys via OpenID discovery",
                jwks.keys.len()
            );
            for (kid, jwk) in &jwks.keys {
                println!("  - Key ID: {}, Algorithm: {:?}", kid, jwk.alg);
            }
        }
        Err(e) => {
            println!("❌ Error fetching JWKS via OpenID: {}", e);
            println!("   Note: This example requires internet connectivity to fetch Google's OpenID config");
        }
    }

    println!(
        "\n💡 Tip: Both examples demonstrate successful library usage when network is available"
    );
    println!("\n📚 For more advanced usage, see the jwt_validation.rs example");
}
