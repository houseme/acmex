//! Strongly-typed ACME identifiers (RFC 8555 §9.7.7, RFC 8738).
//!
//! This module replaces the previous stringly-typed `Identifier`
//! (`{ id_type: String, value: String }`) with a closed enum that makes
//! DNS names, wildcard DNS names and IP addresses impossible to confuse at
//! compile time.
//!
//! * DNS names are normalized: lower-case ASCII (IDNA), no trailing root dot.
//! * Wildcard is an explicit property, only allowed as the left-most label.
//! * IP identifiers use [`std::net::IpAddr`], which yields canonical
//!   IPv4/IPv6 text for free.
//!
//! ACME wire compatibility is preserved: identifiers still serialize as
//! `{"type":"dns"|"ip","value":"..."}`.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use serde::de::{MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Maximum length of a normalized DNS name in ASCII form (RFC 1035).
pub const MAX_DNS_NAME_LEN: usize = 253;
/// Maximum length of a single DNS label.
pub const MAX_LABEL_LEN: usize = 63;

/// Error returned when an identifier cannot be parsed or normalized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentifierError {
    /// The input was empty or contained only whitespace.
    Empty,
    /// The DNS name is structurally invalid (empty label, bad length, ...).
    InvalidDnsName(String),
    /// The wildcard marker is misplaced (only a single left-most `*.` is allowed).
    InvalidWildcard(String),
    /// The value is not a valid IPv4/IPv6 address.
    InvalidIp(String),
    /// The ACME JSON identifier has an unknown `type` field.
    UnknownType(String),
    /// The ACME JSON identifier object is malformed.
    MalformedJson(String),
}

impl fmt::Display for IdentifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "identifier must not be empty"),
            Self::InvalidDnsName(v) => write!(f, "invalid DNS name: {v:?}"),
            Self::InvalidWildcard(v) => {
                write!(
                    f,
                    "invalid wildcard placement (expected `*.<domain>`): {v:?}"
                )
            }
            Self::InvalidIp(v) => write!(f, "invalid IP address: {v:?}"),
            Self::UnknownType(v) => write!(f, "unknown ACME identifier type: {v:?}"),
            Self::MalformedJson(v) => write!(f, "malformed ACME identifier JSON: {v}"),
        }
    }
}

impl std::error::Error for IdentifierError {}

/// A normalized DNS identifier.
///
/// The stored name never contains the `*.` prefix; wildcard-ness is tracked
/// in a dedicated flag so it cannot be lost or faked by string surgery.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DnsIdentifier {
    base: String,
    wildcard: bool,
}

impl DnsIdentifier {
    /// Parses and normalizes a DNS identifier.
    ///
    /// Accepts an optional single left-most wildcard label (`*.example.com`).
    /// The input is normalized (IDNA to lower-case ASCII, trailing root dot
    /// removed) before validation.
    pub fn parse(input: &str) -> Result<Self, IdentifierError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(IdentifierError::Empty);
        }

        let (wildcard, raw_base) = if let Some(rest) = trimmed.strip_prefix("*.") {
            (true, rest)
        } else if trimmed.contains('*') {
            return Err(IdentifierError::InvalidWildcard(trimmed.to_string()));
        } else {
            (false, trimmed)
        };

        let base = normalize_ascii_dns(raw_base)?;
        Self::validate_base(&base).map_err(IdentifierError::InvalidDnsName)?;

        Ok(Self { base, wildcard })
    }

    /// Builds a DNS identifier from an already normalized base name.
    #[allow(dead_code)] // used by later roadmap tasks (zone resolver)
    fn from_normalized_base(base: String, wildcard: bool) -> Self {
        Self { base, wildcard }
    }

    /// Best-effort normalization used by the deprecated compatibility
    /// constructor: lower-cases and strips the trailing dot but performs no
    /// label validation, mirroring the pre-0.9 stringly-typed behavior.
    pub fn parse_lenient(input: &str) -> Self {
        let trimmed = input.trim();
        let (wildcard, raw_base) = match trimmed.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None => (trimmed.contains('*'), trimmed),
        };
        let base = raw_base.trim_end_matches('.').to_ascii_lowercase();
        let base = if base.is_empty() {
            raw_base.to_string()
        } else {
            base
        };
        Self {
            wildcard: wildcard && !base.is_empty(),
            base,
        }
    }

    fn validate_base(base: &str) -> Result<(), String> {
        if base.is_empty() {
            return Err("empty DNS name".to_string());
        }
        if base.len() > MAX_DNS_NAME_LEN {
            return Err(format!("DNS name exceeds {MAX_DNS_NAME_LEN} characters"));
        }
        for label in base.split('.') {
            if label.is_empty() {
                return Err(format!("empty label in {base:?}"));
            }
            if label.len() > MAX_LABEL_LEN {
                return Err(format!(
                    "label exceeds {MAX_LABEL_LEN} characters: {label:?}"
                ));
            }
            if !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return Err(format!("label contains invalid characters: {label:?}"));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(format!(
                    "label must not start or end with a hyphen: {label:?}"
                ));
            }
        }
        Ok(())
    }

    /// The base domain name without any wildcard prefix.
    pub fn base_name(&self) -> &str {
        &self.base
    }

    /// Whether this identifier names a wildcard certificate.
    pub fn is_wildcard(&self) -> bool {
        self.wildcard
    }

    /// The ACME wire value (includes the `*.` prefix for wildcards).
    pub fn to_wire_value(&self) -> String {
        if self.wildcard {
            format!("*.{}", self.base)
        } else {
            self.base.clone()
        }
    }
}

impl fmt::Display for DnsIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_wire_value())
    }
}

impl FromStr for DnsIdentifier {
    type Err = IdentifierError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Normalizes a DNS name to lower-case ASCII (IDNA) without the root dot.
fn normalize_ascii_dns(input: &str) -> Result<String, IdentifierError> {
    let without_dot = input.trim_end_matches('.');
    if without_dot.is_empty() {
        return Err(IdentifierError::Empty);
    }
    if without_dot.is_ascii() {
        // Fast path: pure ASCII only needs case folding.
        return Ok(without_dot.to_ascii_lowercase());
    }
    idna::domain_to_ascii(without_dot)
        .map_err(|_| IdentifierError::InvalidDnsName(input.to_string()))
}

/// Coarse classification used by the challenge compatibility matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum IdentifierKind {
    /// A plain DNS name (`www.example.com`).
    Dns,
    /// A wildcard DNS name (`*.example.com`).
    WildcardDns,
    /// An IPv4 address identifier (RFC 8738).
    Ipv4,
    /// An IPv6 address identifier (RFC 8738).
    Ipv6,
}

/// A strongly-typed ACME identifier.
///
/// Replaces the old `{ id_type: String, value: String }` struct; callers can
/// no longer construct nonsensical combinations (e.g. an "ip" type carrying
/// a hostname) and must go through parsing/normalization.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Identifier {
    /// A DNS name identifier, optionally wildcard.
    Dns(DnsIdentifier),
    /// An IP address identifier (RFC 8738).
    Ip(IpAddr),
}

impl Identifier {
    /// Parses a DNS identifier, validating and normalizing it.
    pub fn try_dns(input: impl AsRef<str>) -> Result<Self, IdentifierError> {
        DnsIdentifier::parse(input.as_ref()).map(Self::Dns)
    }

    /// Parses an IP identifier from its textual form (IPv4 or IPv6).
    pub fn try_ip(input: impl AsRef<str>) -> Result<Self, IdentifierError> {
        let raw = input.as_ref().trim();
        IpAddr::from_str(raw)
            .map(Self::Ip)
            .map_err(|_| IdentifierError::InvalidIp(raw.to_string()))
    }

    /// Parses either identifier kind from free-form input: values that parse
    /// as IP addresses become IP identifiers, everything else is treated as a
    /// DNS name. This never silently turns a syntactically valid IP string
    /// into a DNS identifier.
    pub fn parse(input: impl AsRef<str>) -> Result<Self, IdentifierError> {
        let raw = input.as_ref().trim();
        if raw.is_empty() {
            return Err(IdentifierError::Empty);
        }
        if raw.starts_with('*') {
            return Self::try_dns(raw);
        }
        // `IpAddr::from_str` only accepts exact addresses, so plain hostnames
        // fall through to the DNS branch.
        match IpAddr::from_str(raw) {
            Ok(addr) => Ok(Self::Ip(addr)),
            Err(_) => Self::try_dns(raw),
        }
    }

    /// The kind of this identifier, used for policy decisions.
    pub fn kind(&self) -> IdentifierKind {
        match self {
            Self::Dns(d) if d.is_wildcard() => IdentifierKind::WildcardDns,
            Self::Dns(_) => IdentifierKind::Dns,
            Self::Ip(IpAddr::V4(_)) => IdentifierKind::Ipv4,
            Self::Ip(IpAddr::V6(_)) => IdentifierKind::Ipv6,
        }
    }

    /// Returns `true` when this is a DNS (or wildcard DNS) identifier.
    pub fn is_dns(&self) -> bool {
        matches!(self, Self::Dns(_))
    }

    /// Returns `true` when this is an IP identifier.
    pub fn is_ip(&self) -> bool {
        matches!(self, Self::Ip(_))
    }

    /// Returns `true` only for wildcard DNS identifiers.
    pub fn is_wildcard(&self) -> bool {
        matches!(self, Self::Dns(d) if d.is_wildcard())
    }

    /// The DNS identifier, if this is one.
    pub fn as_dns(&self) -> Option<&DnsIdentifier> {
        match self {
            Self::Dns(d) => Some(d),
            Self::Ip(_) => None,
        }
    }

    /// The IP address, if this is an IP identifier.
    pub fn as_ip(&self) -> Option<IpAddr> {
        match self {
            Self::Ip(addr) => Some(*addr),
            Self::Dns(_) => None,
        }
    }

    /// The ACME wire `type` discriminator.
    pub fn acme_type(&self) -> &'static str {
        match self {
            Self::Dns(_) => "dns",
            Self::Ip(_) => "ip",
        }
    }

    /// The ACME wire `value` (canonical text form).
    pub fn acme_value(&self) -> String {
        match self {
            Self::Dns(d) => d.to_wire_value(),
            Self::Ip(addr) => addr.to_string(),
        }
    }

    /// Lenient constructor used when deserializing CA responses so that
    /// unusual-but-real server data does not break parsing. The stored value
    /// is still normalized where possible.
    pub(crate) fn lenient(acme_type: &str, value: &str) -> Result<Self, IdentifierError> {
        match acme_type {
            "dns" => Ok(Self::Dns(DnsIdentifier::parse_lenient(value))),
            "ip" => Self::try_ip(value),
            other => Err(IdentifierError::UnknownType(other.to_string())),
        }
    }

    /// Deprecated DNS-only compatibility constructor.
    ///
    /// Prefer [`Identifier::try_dns`] (or [`Identifier::parse`]), which
    /// validates the name. This legacy entry point keeps the historical
    /// infallible signature and performs only best-effort normalization, so
    /// existing `Vec<String>` call sites keep compiling.
    #[deprecated(
        since = "0.9.0",
        note = "use `Identifier::try_dns` (validated) or `Identifier::parse` instead; this DNS-only constructor performs no validation"
    )]
    pub fn dns(domain: impl Into<String>) -> Self {
        Self::Dns(DnsIdentifier::parse_lenient(&domain.into()))
    }

    /// Deprecated IP compatibility constructor.
    ///
    /// Prefer [`Identifier::try_ip`]. Unlike [`Identifier::dns`] this method
    /// cannot represent an invalid IP, so it falls back to a loopback
    /// identifier with an error log when the input is unparseable; migrate to
    /// `try_ip` to surface errors properly.
    #[deprecated(
        since = "0.9.0",
        note = "use `Identifier::try_ip` to surface parse errors instead of a silent fallback"
    )]
    pub fn ip(ip: impl Into<String>) -> Self {
        let raw = ip.into();
        match Self::try_ip(&raw) {
            Ok(id) => id,
            Err(err) => {
                tracing::warn!(error = %err, "Identifier::ip received an invalid address");
                Self::Ip(IpAddr::from([127, 0, 0, 1]))
            }
        }
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns(d) => d.fmt(f),
            Self::Ip(addr) => addr.fmt(f),
        }
    }
}

impl From<DnsIdentifier> for Identifier {
    fn from(dns: DnsIdentifier) -> Self {
        Self::Dns(dns)
    }
}

impl From<IpAddr> for Identifier {
    fn from(addr: IpAddr) -> Self {
        Self::Ip(addr)
    }
}

impl FromStr for Identifier {
    type Err = IdentifierError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for Identifier {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("type", self.acme_type())?;
        map.serialize_entry("value", &self.acme_value())?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for Identifier {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct IdentifierVisitor;

        impl<'de> Visitor<'de> for IdentifierVisitor {
            type Value = Identifier;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an ACME identifier object `{type, value}`")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut acme_type: Option<String> = None;
                let mut value: Option<String> = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "type" => acme_type = Some(map.next_value()?),
                        "value" => value = Some(map.next_value()?),
                        _ => {
                            // Unknown members are ignored for forward compatibility.
                            let _ = map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }
                let acme_type = acme_type
                    .ok_or_else(|| serde::de::Error::custom("identifier missing `type`"))?;
                let value =
                    value.ok_or_else(|| serde::de::Error::custom("identifier missing `value`"))?;
                Identifier::lenient(&acme_type, &value)
                    .map_err(|err| serde::de::Error::custom(err.to_string()))
            }
        }

        deserializer.deserialize_map(IdentifierVisitor)
    }
}

/// An ordered, de-duplicated, non-empty set of identifiers.
///
/// Ordering is the canonical `PartialOrd` of [`Identifier`], so the same
/// logical identifier set always hashes and serializes identically
/// regardless of the order in which it was constructed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IdentifierSet {
    items: Vec<Identifier>,
}

impl IdentifierSet {
    /// Builds a set from the given identifiers.
    ///
    /// Returns an error when the input is empty; duplicates are collapsed
    /// (after normalization, so `WWW.example.com` and `www.example.com`
    /// deduplicate to one entry).
    pub fn new(items: Vec<Identifier>) -> Result<Self, IdentifierError> {
        if items.is_empty() {
            return Err(IdentifierError::Empty);
        }
        let mut items = items;
        items.sort();
        items.dedup();
        Ok(Self { items })
    }

    /// Parses free-form strings into a set (IP-looking input becomes IP
    /// identifiers, everything else DNS).
    pub fn parse<I, S>(inputs: I) -> Result<Self, IdentifierError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let items = inputs
            .into_iter()
            .map(|s| Identifier::parse(s))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(items)
    }

    /// The identifiers in canonical order.
    pub fn as_slice(&self) -> &[Identifier] {
        &self.items
    }

    pub fn iter(&self) -> impl Iterator<Item = &Identifier> {
        self.items.iter()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// A stable digest over the canonical set, used as the logical
    /// certificate identity (e.g. to correlate a lineage with its intent).
    pub fn normalized_hash(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for id in &self.items {
            hasher.update(id.acme_type().as_bytes());
            hasher.update([0]);
            hasher.update(id.acme_value().as_bytes());
            hasher.update([0]);
        }
        hex::encode(hasher.finalize())
    }

    /// Returns `true` if any identifier is a wildcard DNS name.
    pub fn contains_wildcard(&self) -> bool {
        self.items.iter().any(|id| id.is_wildcard())
    }

    /// Returns `true` if any identifier is an IP address.
    pub fn contains_ip(&self) -> bool {
        self.items.iter().any(|id| id.is_ip())
    }
}

impl<'a> IntoIterator for &'a IdentifierSet {
    type Item = &'a Identifier;
    type IntoIter = std::slice::Iter<'a, Identifier>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.iter()
    }
}

impl Serialize for IdentifierSet {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.items.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for IdentifierSet {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let items = Vec::<Identifier>::deserialize(deserializer)?;
        Self::new(items).map_err(|err| serde::de::Error::custom(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_normalizes_case_and_trailing_dot() {
        let id = Identifier::try_dns("WWW.Example.COM.").unwrap();
        assert_eq!(id.acme_value(), "www.example.com");
        assert_eq!(id.kind(), IdentifierKind::Dns);
    }

    #[test]
    fn parse_idn_to_ascii() {
        let id = Identifier::try_dns("ExÄmple.example.com").unwrap();
        assert_eq!(id.acme_value(), "xn--exmple-cua.example.com");
        // Purely ASCII input skips the IDNA pipeline but still normalizes.
        let ascii = Identifier::try_dns("MIXED.Case.Example.COM").unwrap();
        assert_eq!(ascii.acme_value(), "mixed.case.example.com");
    }

    #[test]
    fn wildcard_is_explicit() {
        let id = Identifier::try_dns("*.Example.com").unwrap();
        assert!(id.is_wildcard());
        assert_eq!(id.acme_value(), "*.example.com");
        assert_eq!(id.kind(), IdentifierKind::WildcardDns);
        assert_eq!(id.as_dns().unwrap().base_name(), "example.com");
    }

    #[test]
    fn rejects_misplaced_wildcard() {
        assert!(Identifier::try_dns("www.*.example.com").is_err());
        assert!(Identifier::try_dns("*.*.example.com").is_err());
        assert!(Identifier::try_dns("example.*").is_err());
        assert!(Identifier::try_dns("example.com*").is_err());
    }

    #[test]
    fn rejects_invalid_dns_names() {
        assert_eq!(Identifier::try_dns(""), Err(IdentifierError::Empty));
        assert!(Identifier::try_dns(".example.com").is_err());
        assert!(Identifier::try_dns("example..com").is_err());
        assert!(Identifier::try_dns("-bad.example.com").is_err());
        assert!(Identifier::try_dns("bad-.example.com").is_err());
        assert!(Identifier::try_dns("a".repeat(64)).is_err());
        assert!(Identifier::try_dns("under_score.example.com").is_err());
    }

    #[test]
    fn parses_ipv4_and_ipv6() {
        let v4 = Identifier::try_ip("192.0.2.1").unwrap();
        assert_eq!(v4.kind(), IdentifierKind::Ipv4);
        assert_eq!(v4.acme_value(), "192.0.2.1");

        let v6 = Identifier::try_ip("2001:0DB8:0000:0000:0000:0000:0000:0001").unwrap();
        assert_eq!(v6.kind(), IdentifierKind::Ipv6);
        assert_eq!(v6.acme_value(), "2001:db8::1");

        let inner = v6.as_ip().unwrap();
        assert!(inner.is_ipv6());
    }

    #[test]
    fn auto_parse_detects_ip_vs_dns() {
        let ip = Identifier::parse("192.0.2.1").unwrap();
        assert!(ip.is_ip());
        let dns = Identifier::parse("example.com").unwrap();
        assert!(dns.is_dns());
        let wild = Identifier::parse("*.example.com").unwrap();
        assert!(wild.is_wildcard());
    }

    #[test]
    fn acme_json_roundtrip() {
        let dns = Identifier::try_dns("*.Example.com").unwrap();
        let json = serde_json::to_value(&dns).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"type": "dns", "value": "*.example.com"})
        );
        let back: Identifier = serde_json::from_value(json).unwrap();
        assert_eq!(back, dns);

        let ip = Identifier::try_ip("2001:db8::1").unwrap();
        let json = serde_json::to_value(&ip).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"type": "ip", "value": "2001:db8::1"})
        );
        let back: Identifier = serde_json::from_value(json).unwrap();
        assert_eq!(back, ip);
    }

    #[test]
    fn acme_json_rejects_unknown_type() {
        let err = serde_json::from_value::<Identifier>(serde_json::json!({
            "type": "fnord",
            "value": "x"
        }));
        assert!(err.is_err());
    }

    #[test]
    fn dns_and_ip_with_same_text_are_distinct() {
        let dns = Identifier::try_dns("1.2.3.4").unwrap();
        let ip = Identifier::try_ip("1.2.3.4").unwrap();
        assert_ne!(dns, ip);
        assert!(dns.is_dns());
        assert!(ip.is_ip());
    }

    #[test]
    fn deprecated_constructors_still_work() {
        #[allow(deprecated)]
        let id = Identifier::dns("WWW.Example.COM.");
        assert_eq!(id.acme_value(), "www.example.com");
        #[allow(deprecated)]
        let ip = Identifier::ip("192.0.2.1");
        assert!(ip.is_ip());
    }

    #[test]
    fn wire_compat_with_legacy_json() {
        // The exact JSON shape used before 0.9 must keep deserializing.
        let id: Identifier = serde_json::from_value(serde_json::json!({
            "type": "dns",
            "value": "example.com"
        }))
        .unwrap();
        assert_eq!(id.acme_value(), "example.com");
    }

    #[test]
    fn identifier_set_dedupes_and_sorts_stably() {
        let a = IdentifierSet::new(vec![
            Identifier::try_dns("www.example.com").unwrap(),
            Identifier::try_dns("WWW.example.com").unwrap(),
            Identifier::try_dns("example.com").unwrap(),
            Identifier::try_ip("192.0.2.1").unwrap(),
        ])
        .unwrap();
        assert_eq!(a.len(), 3);

        let b = IdentifierSet::new(vec![
            Identifier::try_ip("192.0.2.1").unwrap(),
            Identifier::try_dns("example.com").unwrap(),
            Identifier::try_dns("www.example.com").unwrap(),
        ])
        .unwrap();
        assert_eq!(a, b);
        assert_eq!(a.normalized_hash(), b.normalized_hash());
        assert!(a.contains_ip());
        assert!(!a.contains_wildcard());
    }

    #[test]
    fn identifier_set_rejects_empty() {
        assert_eq!(
            IdentifierSet::new(Vec::new()).unwrap_err(),
            IdentifierError::Empty
        );
    }

    #[test]
    fn identifier_set_json_roundtrip() {
        let set = IdentifierSet::parse(["*.example.com", "192.0.2.1"]).unwrap();
        let json = serde_json::to_string(&set).unwrap();
        let back: IdentifierSet = serde_json::from_str(&json).unwrap();
        assert_eq!(set, back);
        assert!(set.contains_wildcard());
    }
}
