# AcmeX Cryptography Guide

This document describes the cryptographic implementations and patterns used in AcmeX.

## 1. Signer Trait

The `Signer` trait is the core abstraction for all signing operations (JWS, HMAC, etc.).

```rust
pub trait Signer: Send + Sync {
    fn sign(&self, data: &[u8]) -> Result<Signature>;
    fn algorithm(&self) -> &str;
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool>;
}
```

## 2. HMAC Implementation

HMAC (Hash-based Message Authentication Code) is primarily used in ACME for **External Account Binding (EAB)**.

### Supported Algorithms
- **HS256**: HMAC using SHA-256.

### Usage Example

```rust
use acmex::crypto::signer::{HmacSigner, Signer};

let key = b"your-secret-key".to_vec();
let signer = HmacSigner::hs256(key);

let data = b"payload to sign";
let signature = signer.sign(data).expect("Signing failed");

println!("Algorithm: {}", signature.algorithm);
println!("Base64 Signature: {}", signature.to_base64());
```

## 3. Security Considerations

- **Key Zeroization**: Sensitive keys should be zeroized when dropped (using the `zeroize` crate).
- **Constant Time**: Verification uses `verify_slice` from the `hmac` crate, which provides constant-time comparison to prevent timing attacks.
- **Algorithm Agility**: The `Signer` trait allows for easy addition of new algorithms (e.g., HS384, HS512) without changing the orchestration logic.

## 4. Integration with ACME EAB

When creating an account with External Account Binding:
1. The CA provides a `Key ID` and a `MAC Key`.
2. The `MAC Key` (Base64URL encoded) is used to create an `HmacSigner`.
3. The signer signs the JWS Key of the new account to prove possession of the external account.
