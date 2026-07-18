use alloc::collections::BTreeMap;

/// Parsed TOML configuration.
#[derive(Debug, Clone)]
pub struct TomlConfig {
    sections: BTreeMap<alloc::string::String, BTreeMap<alloc::string::String, ConfigValue>>,
}

#[derive(Debug, Clone)]
pub enum ConfigValue {
    Integer(i64),
    Boolean(bool),
    String(alloc::string::String),
}

impl TomlConfig {
    pub fn new() -> Self {
        Self {
            sections: BTreeMap::new(),
        }
    }

    pub fn get_int(&self, section: &str, key: &str) -> Option<i64> {
        match self.sections.get(section)?.get(key)? {
            ConfigValue::Integer(v) => Some(*v),
            _ => None,
        }
    }

    pub fn get_bool(&self, section: &str, key: &str) -> Option<bool> {
        match self.sections.get(section)?.get(key)? {
            ConfigValue::Boolean(v) => Some(*v),
            _ => None,
        }
    }

    pub fn get_str(&self, section: &str, key: &str) -> Option<&str> {
        match self.sections.get(section)?.get(key)? {
            ConfigValue::String(v) => Some(v.as_str()),
            _ => None,
        }
    }
}

pub fn parse_toml(data: &[u8]) -> Result<TomlConfig, &'static str> {
    let text = core::str::from_utf8(data).map_err(|_| "invalid UTF-8 in TOML")?;
    let mut config = TomlConfig::new();
    let mut sec = alloc::string::String::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            if name.contains('.') {
                return Err("nested tables not supported");
            }
            sec = alloc::string::String::from(name);
            config.sections.entry(sec.clone()).or_default();
            continue;
        }
        let (key, val) = line.split_once('=').ok_or("invalid TOML syntax")?;
        let key = key.trim();
        let val = val.trim();
        let v = if val == "true" {
            ConfigValue::Boolean(true)
        } else if val == "false" {
            ConfigValue::Boolean(false)
        } else if let Some(hex) = val.strip_prefix("0x").or_else(|| val.strip_prefix("0X")) {
            ConfigValue::Integer(i64::from_str_radix(hex, 16).map_err(|_| "invalid hex")?)
        } else if val.starts_with('"') && val.ends_with('"') {
            ConfigValue::String(alloc::string::String::from(&val[1..val.len() - 1]))
        } else {
            ConfigValue::Integer(val.parse().map_err(|_| "invalid integer")?)
        };
        config
            .sections
            .entry(sec.clone())
            .or_default()
            .insert(alloc::string::String::from(key), v);
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple() {
        let toml = b"
# Comment
[buddy]
compaction_threshold = 35
";
        let config = parse_toml(toml).unwrap();
        assert_eq!(config.get_int("buddy", "compaction_threshold"), Some(35));
    }

    #[test]
    fn test_parse_multiple_sections() {
        let toml = b"
[section1]
key1 = 100
key2 = true

[section2]
key3 = \"hello\"
";
        let config = parse_toml(toml).unwrap();
        assert_eq!(config.get_int("section1", "key1"), Some(100));
        assert_eq!(config.get_bool("section1", "key2"), Some(true));
        assert_eq!(config.get_str("section2", "key3"), Some("hello"));
    }

    #[test]
    fn test_parse_hex() {
        let toml = b"
[test]
value = 0xFF
";
        let config = parse_toml(toml).unwrap();
        assert_eq!(config.get_int("test", "value"), Some(255));
    }
}
