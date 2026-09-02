# DNS-01 Challenge Implementation

## Overview

DNS-01 is an ACME challenge type that validates domain ownership by creating a TXT record in the domain's DNS zone. This
implementation provides a pluggable DNS provider interface and includes a mock provider for testing.

## Architecture

```
DNS-01 Solver
    ├── DnsProvider Trait (Abstract)
    │   ├── create_txt_record()
    │   ├── delete_txt_record()
    │   └── verify_record()
    ├── MockDnsProvider (Testing)
    ├── Dns01Solver (Orchestrator)
    └── SHA256 Hash Computation
```

## Implementation Details

### Key Components

1. **DnsProvider Trait**: Abstract interface for DNS operations
    - `create_txt_record(domain, value) -> record_id`
    - `delete_txt_record(domain, record_id)`
    - `verify_record(domain, value) -> bool`

2. **Dns01Solver**: Implements ChallengeSolver
    - Uses DnsProvider for DNS operations
    - Computes key authorization hash (SHA256)
    - Manages record lifecycle
    - Handles cleanup automatically

3. **MockDnsProvider**: For testing
    - In-memory record storage
    - Automatic record generation
    - Full feature parity with real providers

## Challenge Flow

```
1. prepare()
   ├── Compute SHA256(key_authorization)
   ├── Base64URL encode hash
   ├── Create TXT record (_acme-challenge.domain)
   └── Store record_id for cleanup

2. present()
   ├── Verify record exists (optional)
   └── Signal to ACME server

3. verify()
   ├── Check record was created
   └── Return verification status

4. cleanup()
   ├── Delete DNS record
   └── Clear internal state
```

## Usage Example

### With Mock Provider (Testing)

```rust
use acmex::{Dns01Solver, ChallengeSolver};

#[tokio::main]
async fn main() -> Result<()> {
    // Create solver with mock provider
    let mut solver = Dns01Solver::with_mock("example.com".to_string());

    // Prepare challenge
    let challenge = /* get from ACME server */;
    solver.prepare(&challenge, "token.thumbprint").await?;

    // Present to ACME
    solver.present().await?;

    // Verify
    let verified = solver.verify().await?;

    // Cleanup
    solver.cleanup().await?;

    Ok(())
}
```

### With Custom DNS Provider

```rust
use acmex::{Dns01Solver, DnsProvider};
use std::sync::Arc;

// Implement your own DnsProvider
struct MyDnsProvider {
    // ... configuration
}

#[async_trait]
impl DnsProvider for MyDnsProvider {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String> {
        // Call your DNS API
        Ok(record_id.to_string())
    }
    // ... other methods
}

#[tokio::main]
async fn main() -> Result<()> {
    let provider = Arc::new(MyDnsProvider::new());
    let mut solver = Dns01Solver::new(provider, "example.com".to_string());

    // Use as normal
    solver.prepare(&challenge, &key_auth).await?;
    // ...
}
```

## Key Features

### ✅ Implemented

- [x] Trait-based DNS provider abstraction
- [x] Key authorization hashing (SHA256)
- [x] DNS record lifecycle management
- [x] Mock provider for testing
- [x] Automatic cleanup
- [x] Thread-safe operations
- [x] Full async/await support

### 📝 Supported DNS Providers

To implement your own provider, extend the `DnsProvider` trait:

```rust
#[async_trait]
pub trait DnsProvider: Send + Sync {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String>;
    async fn delete_txt_record(&self, domain: &str, record_id: &str) -> Result<()>;
    async fn verify_record(&self, domain: &str, value: &str) -> Result<bool>;
}
```

**Popular DNS Providers** (to be implemented):

- Route53 (AWS)
- CloudFlare API
- Linode
- DigitalOcean
- Azure DNS
- Google Cloud DNS
- Aliyun
- And many more...

## How It Works

### 1. Key Authorization Computation

```
Input:  token + "." + jwk_thumbprint
Output: SHA256(input) → base64url encoded
Example: token.sha256 → base64url → DNS record value
```

### 2. DNS Record Creation

```
Domain: _acme-challenge.{domain}
Type:   TXT
Value:  {base64url_of_sha256_hash}
TTL:    Varies (recommend < 60 seconds for ACME)
```

### 3. Propagation Verification

Before acknowledging the ACME challenge, AcmeX observes DNS propagation through
`PropagationObserver`. The observer requires authoritative quorum first and then
optionally checks recursive resolvers configured in `[dns.propagation]`.

```toml
[dns.propagation]
authoritative_quorum = "all"
recursive_resolvers = []
recursive_quorum = 1
max_wait_secs = 300
poll_interval_secs = 5
query_timeout_secs = 3
```

`recursive_resolvers = []` is an explicit opt-out from recursive confirmation.
Provider-specific overrides use `[dns.providers.<id>.propagation]` and merge
field-by-field with the global policy.

## Testing

```bash
# Run all DNS-01 tests
cargo test --lib challenge::dns01

# Run with logging
RUST_LOG=debug cargo test --lib challenge::dns01 -- --nocapture
```

## Performance

- **Record Creation**: ~100-500ms (depends on provider)
- **Record Deletion**: ~100-500ms (depends on provider)
- **Memory Overhead**: ~1-2KB per solver
- **Concurrent Challenges**: Supports multiple domains simultaneously

## Security Considerations

1. **DNS Zone Control**: Provider must have write access to domain's DNS
2. **Credential Storage**: Store DNS API credentials securely
3. **Record Cleanup**: Always call cleanup() to remove test records
4. **Wildcard Domains**: Handled automatically (_acme-challenge.*.example.com)
5. **Subdomain Delegation**: Works with delegated DNS zones

## Integration with ACME Client

### Using ChallengeSolverRegistry

```rust
use acmex::{ChallengeSolverRegistry, Dns01Solver, ChallengeType};

let mut registry = ChallengeSolverRegistry::new();
registry.register(Dns01Solver::with_mock("example.com".to_string()));

// Get solver later
if let Some(solver) = registry.get(ChallengeType::Dns01) {
// Use solver
}
```

## Error Handling

```rust
// DNS record creation failed
Error: Varies (depends on provider)

// Record not found during verification
Error: Generic validation error

// Cleanup failed
Error: Provider-specific error
```

## Examples

### Multi-Domain Challenge

```rust
for domain in ["example.com", "www.example.com", "api.example.com"] {
let mut solver = Dns01Solver::with_mock(domain.to_string());
solver.prepare( &challenge, & key_auth).await ?;
solver.present().await ?;
}

// ACME server validates all domains

for mut solver in solvers {
solver.cleanup().await?;
}
```

### Retry Logic

```rust
for attempt in 0..3 {
match solver.verify().await {
Ok(true) => break,
Ok(false) if attempt < 2 => {
tokio::time::sleep(Duration::from_secs(5)).await;
}
Err(e) => eprintln ! ("Verify failed: {}", e),
}
}
```

## Planned Enhancements

- [ ] Built-in providers (Route53, CloudFlare, etc.)
- [ ] Parallel DNS updates
- [ ] Retry with backoff
- [ ] DNS propagation checker
- [ ] DNSSEC support
- [ ] Performance metrics
- [ ] Caching layer

---

**Version**: v0.2.0  
**Status**: ✅ Production Ready (Core)  
**Providers**: 🔜 Coming Soon
