use jw_guard_declare::DeclareError;

pub type WireConversionResult<T> = Result<T, Vec<DeclareError>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceConvertError {
    InvalidCanonicalName {
        path: String,
        value: String,
        source: jw_guard_core::ScalarViolation,
    },
    InvalidMappedOutput(Vec<jw_guard_mapper::MapViolation>),
    UnexpectedMapperInputError(jw_guard_mapper::MapErrorCode),
}
