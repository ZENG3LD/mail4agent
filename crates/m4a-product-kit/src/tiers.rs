//! Tier names -> the opaque flag the messenger's policy hook may read.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct TierTable {
    flags: HashMap<String, u8>,
    default_tier: String,
}

impl Default for TierTable {
    fn default() -> Self {
        Self::parse("free=0,paid=1").expect("static table")
    }
}

impl TierTable {
    /// `name=0|1` pairs, comma separated; the first name is the default for new users.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let mut flags = HashMap::new();
        let mut default_tier = String::new();
        for part in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let (n, f) = part.split_once('=').ok_or_else(|| format!("tier entry {part:?} needs name=0|1"))?;
            let f: u8 = match f.trim() {
                "0" => 0,
                "1" => 1,
                _ => return Err(format!("tier {n:?}: flag must be 0 or 1")),
            };
            if default_tier.is_empty() {
                default_tier = n.trim().to_string();
            }
            flags.insert(n.trim().to_string(), f);
        }
        if flags.is_empty() {
            return Err("tier table is empty".into());
        }
        Ok(Self { flags, default_tier })
    }
    /// `M4A_PRODUCT_TIERS`, default `free=0,paid=1`.
    pub fn from_env() -> Result<Self, String> {
        match std::env::var("M4A_PRODUCT_TIERS") {
            Ok(v) if !v.is_empty() => Self::parse(&v),
            _ => Ok(Self::default()),
        }
    }
    pub fn default_tier(&self) -> &str {
        &self.default_tier
    }
    pub fn knows(&self, tier: &str) -> bool {
        self.flags.contains_key(tier)
    }
    /// Unknown tiers read as 0.
    pub fn flag(&self, tier: &str) -> u8 {
        self.flags.get(tier).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parse_and_flags() {
        let t = TierTable::parse("basic=0, plus=1").unwrap();
        assert_eq!((t.default_tier(), t.flag("plus"), t.flag("basic"), t.flag("zzz")), ("basic", 1, 0, 0));
        assert!(TierTable::parse("").is_err() && TierTable::parse("a=2").is_err() && TierTable::parse("a").is_err());
    }
}
