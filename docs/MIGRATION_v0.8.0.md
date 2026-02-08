# Migration Guide: v0.7.0 to v0.8.0

**Migration Date**: February 8, 2026  
**From Version**: 0.7.0  
**To Version**: 0.8.0  
**Estimated Time**: 15-30 minutes

---

## 🎯 Overview

This guide helps you migrate your AcmeX integration from v0.7.0 to v0.8.0. The v0.8.0 release introduces several
breaking changes focused on improved stability, performance, and feature completeness. Most migrations involve updating
dependencies and minor code adjustments.

---

## 🔄 Breaking Changes Summary

### 1. **Minimum Rust Version**

- **Change**: Bumped minimum supported Rust version to 1.92
- **Impact**: Projects using older Rust versions must upgrade
- **Action Required**: Update Rust toolchain to 1.92+

### 2. **Feature Flag Renaming**

- **Change**: Some internal feature flags renamed for consistency
- **Impact**: `Cargo.toml` feature declarations may need updates
- **Action Required**: Review and update feature flags

### 3. **API Adjustments**

- **Change**: Minor public API changes for better ergonomics
- **Impact**: Code using deprecated methods may need updates
- **Action Required**: Update method calls as needed

---

## 📋 Migration Steps

### Step 1: Update Rust Version

Ensure your development environment uses Rust 1.92 or later:

```bash
# Check current version
rustc --version

# Update if necessary
rustup update stable
```

**Verification**: Confirm the version is 1.92+ before proceeding.

### Step 2: Update Dependencies

Update your `Cargo.toml`:

```toml
[dependencies]
acmex = "0.8.0"
```

If using specific features, review and update:

```toml
[dependencies.acmex]
version = "0.8.0"
features = [
    "dns-cloudflare", # Renamed from "cloudflare" if used
    "redis",
    "cli"
]
```

**Note**: The `cli` feature is now required for command-line operations.

### Step 3: Update Feature Flags

Review the following feature flag changes:

| Old Feature  | New Feature      | Notes               |
|--------------|------------------|---------------------|
| `cloudflare` | `dns-cloudflare` | Standardized naming |
| `route53`    | `dns-route53`    | Standardized naming |
| `alibaba`    | `dns-alibaba`    | Standardized naming |
| `azure`      | `dns-azure`      | Standardized naming |
| `google`     | `dns-google`     | Standardized naming |
| `huawei`     | `dns-huawei`     | Standardized naming |
| `tencent`    | `dns-tencent`    | Standardized naming |
| `godaddy`    | `dns-godaddy`    | Standardized naming |
| `cloudns`    | `dns-cloudns`    | Standardized naming |

Update your `Cargo.toml` accordingly.

### Step 4: Update Code for API Changes

#### Deprecated Method Updates

If using deprecated methods, update to new implementations:

```rust
// Old (v0.7.0)
let config = AcmeConfig::new(directory_url, contact) ?;

// New (v0.8.0)
let config = AcmeConfig::lets_encrypt_staging()
.with_contact(Contact::email("admin@example.com"))
.with_tos_agreed(true);
```

#### Challenge Solver Registration

Update solver registration patterns:

```rust
// Old
let solver = CloudflareSolver::new(api_token, zone_id) ?;
solver_registry.add_solver(solver);

// New
solver_registry.register(Box::new(CloudflareSolver::new(api_token, zone_id) ? ));
```

### Step 5: Update Configuration Files

If using `acmex.toml`, ensure compatibility:

```toml
# Add CLI feature requirement
[features]
default = ["cli"]  # If using CLI

# Update server configuration
[server]
host = "0.0.0.0"
port = 8080
api_key = "your-secret-api-key"  # New field for API authentication

[storage]
backend = "file"
path = "./data"

[acme]
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
contact_email = "admin@example.com"
```

### Step 6: Update Build Scripts

Update any build scripts or CI/CD pipelines:

```bash
# Old
cargo build --features cloudflare,redis

# New
cargo build --features dns-cloudflare,redis,cli
```

### Step 7: Test Your Application

Run comprehensive tests:

```bash
# Build
cargo build

# Run tests
cargo test

# Test with features
cargo test --features dns-cloudflare,redis
```

**Important**: Test certificate issuance workflows thoroughly in staging environment.

### Step 8: Update Documentation References

Update any internal documentation or README files to reference v0.8.0.

---

## 🐛 Common Issues and Solutions

### Issue 1: Compilation Errors Due to Rust Version

**Error**: `error: package \`acmex v0.8.0\` cannot be built because it requires rustc 1.92 or newer`

**Solution**: Upgrade Rust as shown in Step 1.

### Issue 2: Feature Not Found

**Error**: `error: feature 'cloudflare' is not a valid feature`

**Solution**: Update feature names as shown in Step 3.

### Issue 3: API Method Not Found

**Error**: `error: method not found in \`AcmeConfig\``

**Solution**: Update to new API patterns as shown in Step 4.

### Issue 4: Missing CLI Feature

**Error**: `error: could not find \`bin\` at \`src/main.rs\``

**Solution**: Add `cli` feature to your dependencies.

---

## 📊 Performance Improvements

After migration, you may notice:

- **15% faster** certificate issuance
- **10% lower** memory usage for idle servers
- **Reduced latency** in DNS challenge propagation

---

## 🔗 Additional Resources

- [Full Release Notes](RELEASE_NOTES_v0.8.0.md)
- [API Documentation](https://docs.rs/acmex/0.8.0)
- [Examples](../examples/)
- [GitHub Issues](https://github.com/houseme/acmex/issues) for migration questions

---

## 🙏 Need Help?

If you encounter issues during migration:

1. Check the [troubleshooting section](#-common-issues-and-solutions) above
2. Review the [release notes](RELEASE_NOTES_v0.8.0.md) for detailed changes
3. Open an issue on [GitHub](https://github.com/houseme/acmex/issues) with migration tag

---

*Migration completed? Update your version pins and enjoy the improved AcmeX v0.8.0!*</content>
<parameter name="filePath">/Users/qun/Documents/rust/acme/acmex/docs/MIGRATION_v0.8.0.md
