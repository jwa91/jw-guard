use jw_guard_declare::DeclareError;

pub type WireConversionResult<T> = Result<T, Vec<DeclareError>>;
