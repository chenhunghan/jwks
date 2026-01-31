//! Helper script to generate a mock JWT for testing purposes
//!
//! This creates a JWT with the correct structure using Google's Key ID
//! Note: This JWT won't have a valid signature since we don't have Google's private key,
//! but it demonstrates the validation flow

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::json;

fn main() {
    // JWT Header - using Google's actual Key ID
    let header = json!({
        "alg": "RS256",
        "typ": "JWT",
        "kid": "07f078f2647e8cd019c40da9569e4f5247991094"  // Google's current key ID
    });

    // JWT Payload - typical Google OAuth2 claims
    let now = chrono::Utc::now().timestamp();
    let payload = json!({
        "iss": "https://accounts.google.com",
        "azp": "your-client-id.apps.googleusercontent.com",
        "aud": "your-client-id.apps.googleusercontent.com",
        "sub": "123456789",
        "email": "user@example.com",
        "email_verified": true,
        "at_hash": "example_hash",
        "name": "Test User",
        "picture": "https://example.com/photo.jpg",
        "given_name": "Test",
        "family_name": "User",
        "locale": "en",
        "iat": now,
        "exp": now + 3600, // 1 hour expiration
        "jti": "example-jti-123456"
    });

    // Create mock JWT (without valid signature)
    let header_encoded = URL_SAFE_NO_PAD.encode(header.to_string());
    let payload_encoded = URL_SAFE_NO_PAD.encode(payload.to_string());

    // Mock signature part (base64 of dummy data)
    let mock_signature = URL_SAFE_NO_PAD.encode("mock_signature_data");

    let jwt = format!("{}.{}.{}", header_encoded, payload_encoded, mock_signature);

    println!("Mock JWT for testing:");
    println!("{}", jwt);
    println!("\n📝 Usage:");
    println!("   Copy this JWT and use it in the jwt_validation.rs example");
    println!("   to demonstrate the validation flow with Google's actual JWKS.");
    println!("\n🔍 Note: This JWT has the correct structure and uses Google's actual Key ID,");
    println!("   but the signature is invalid since we don't have Google's private key.");
    println!("   This is perfect for demonstrating the validation workflow!");
}
