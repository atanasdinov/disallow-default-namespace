use std::{error, fmt};
use std::fmt::Formatter;

#[derive(Debug)]
pub enum ResourceError {
    NonWorkloadError,
    SerdeJsonError(serde_json::Error),
}

impl fmt::Display for ResourceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            ResourceError::NonWorkloadError => write!(f, "resource is not a workload"),
            ResourceError::SerdeJsonError(..) => write!(f, "failed to deserialize resource"),
        }
    }
}

impl error::Error for ResourceError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            ResourceError::NonWorkloadError => None,
            // The cause is the underlying implementation error type. Is implicitly
            // cast to the trait object `&error::Error`. This works because the
            // underlying type already implements the `Error` trait.
            ResourceError::SerdeJsonError(ref e) => Some(e),
        }
    }
}

impl From<serde_json::Error> for ResourceError {
    fn from(err: serde_json::Error) -> ResourceError {
        ResourceError::SerdeJsonError(err)
    }
}
