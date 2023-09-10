# JWT Token Creation in Rust

This Rust code demonstrates how to create JWT (JSON Web Token) tokens using various algorithms, including HMAC and RSA. JWT is a widely used standard for securely transmitting information between parties.

## Prerequisites

Before running this code, ensure you have the following dependencies:

- Rust (https://www.rust-lang.org/tools/install)
- Cargo (Rust package manager, typically installed with Rust)
- Required Rust crates (add them to your `Cargo.toml` file):
  - `serde`: Serialization and deserialization library (https://crates.io/crates/serde)
  - `rsa`: RSA cryptography library (https://crates.io/crates/rsa)
  - `serde_json`: JSON serialization and deserialization for Rust (https://crates.io/crates/serde_json)
  - `base64`: Base64 encoding and decoding (https://crates.io/crates/base64)
  - `chrono`: Date and time library for Rust (https://crates.io/crates/chrono)
  - `jwt_compact`: JWT library for Rust (https://crates.io/crates/jwt_compact)

You can add these dependencies to your `Cargo.toml` as follows:

```toml
[dependencies]
serde = "1.0"
rsa = "0.9"
serde_json = "1.0"
base64 = "0.13"
chrono = "0.4"
jwt_compact = "3.1"

## Code Overview
This code includes the following main components:

## CustomClaims Struct
A custom struct CustomClaims is defined to represent JWT claims, including subject, issuer, audience, expiration, and additional claims. This struct allows you to create JWT tokens with custom claims.

## generate_jwt_token Function
The generate_jwt_token function creates JWT tokens based on the selected algorithm, such as HMAC (HS256) or RSA (RS256-PKCS#1, RS256-PKCS#1.5, or RS256-PKCS#8). It takes parameters like the algorithm, subject, issuer, expiration, audience, and additional claims.

## create_hmac_token Function
The create_hmac_token function generates HMAC-based JWT tokens using the jwt_compact crate. It utilizes a secret key for token creation and supports custom claims.

## create_rsa_token Function
The create_rsa_token function generates RSA-based JWT tokens. It includes the steps to sign the token using an RSA private key and supports custom claims.

## RSA Key Handling
RSA keys are loaded based on the selected algorithm (RS256-PKCS#1, RS256-PKCS#1.5, or RS256-PKCS#8) using the rsa crate. Key handling is done in the create_rsa_key function.

## Running the Code
To run the code, execute the main function. It generates JWT tokens using various algorithms, including HMAC and RSA. The resulting tokens are printed to the console.
