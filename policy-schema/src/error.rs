use alloc::string::String;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicySchemaError {
    YamlParse(String),
}

#[cfg(feature = "yaml")]
impl From<serde_yaml::Error> for PolicySchemaError {
    fn from(value: serde_yaml::Error) -> Self {
        Self::YamlParse(value.to_string())
    }
}
