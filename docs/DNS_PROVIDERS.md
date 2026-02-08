# AcmeX DNS Providers Guide

AcmeX supports a wide range of DNS providers for automated DNS-01 challenge fulfillment.

## Supported Providers

| Provider | Feature Flag | Configuration Requirements |
|----------|--------------|----------------------------|
| Cloudflare | `dns-cloudflare` | API Token, Zone ID |
| Route53 | `dns-route53` | AWS Credentials, Hosted Zone ID |
| Tencent Cloud (DNSPod) | `dns-tencent` | SecretId, SecretKey |
| Huawei Cloud | `dns-huawei` | AccessKey, SecretKey, ProjectId, Region |
| Google Cloud DNS | `dns-google` | Project ID, Service Account (optional) |

## Provider Details

### Cloudflare
Uses the Cloudflare API v4. Requires an API Token with `Zone.DNS` permissions.

### Route53
Uses the official AWS SDK. Supports standard AWS credential resolution (env vars, IAM roles, etc.).

### Tencent Cloud (DNSPod)
Uses Tencent Cloud API v3 with TC3-HMAC-SHA256 signing.
- **Domain resolution**: Automatically splits subdomains from the main domain.
- **Record Management**: Supports `CreateRecord`, `DeleteRecord`, and `DescribeRecordList`.

### Huawei Cloud
Uses Huawei Cloud API with SDK-HMAC-SHA256 signing.
- **Region-specific**: Requires specifying the region (e.g., `cn-north-4`).

## Implementation Standards

All DNS providers in AcmeX must implement the `DnsProvider` trait:

```rust
#[async_trait]
pub trait DnsProvider: Send + Sync {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String>;
    async fn delete_txt_record(&self, domain: &str, record_id: &str) -> Result<()>;
    async fn verify_record(&self, domain: &str, value: &str) -> Result<bool>;
}
```

### Security Best Practices
1. **Credential Isolation**: Use environment variables or encrypted storage for API keys.
2. **Least Privilege**: API tokens should only have permissions to manage DNS records for the specific zones required.
3. **Cleanup**: Always implement `delete_txt_record` to remove challenge records after validation.
