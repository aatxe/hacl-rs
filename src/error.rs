use std::result;

use failure::Error;

#[derive(Debug, Fail)]
pub enum CryptoError {
    #[fail(display = "failed to verify ")]
    VerificationFailed,
}

pub type Result<T> = result::Result<T, Error>;
