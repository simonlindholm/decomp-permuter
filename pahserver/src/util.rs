use std::error::Error;

pub type SimpleResult<T> = Result<T, Box<dyn Error + Send + Sync>>;
