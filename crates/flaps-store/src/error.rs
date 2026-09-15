//! Store-level error type and result alias.

/// Errors produced by the persistence layer.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// A database driver error.
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),
    /// A JSON serialization or deserialization error.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    /// A migration failed.
    #[error("migration error: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    /// The requested entity does not exist.
    #[error("entity not found")]
    NotFound,
    /// A uniqueness constraint was violated.
    #[error("conflict: {0}")]
    Conflict(String),
    /// A write referenced a parent entity that does not exist (foreign-key violation).
    #[error("referenced entity does not exist")]
    ForeignKeyViolation,
    /// A cryptographic operation (password hashing or random byte generation) failed.
    #[error("crypto error: {0}")]
    Crypto(String),
    /// A stored record does not conform to the domain's invariants: an
    /// unrecognized enum tag, or a key that no longer parses. Distinct from
    /// [`Self::Serialization`], which covers JSON encode/decode failures
    /// rather than a value that decoded fine but violates a domain rule.
    #[error("corrupt record: {0}")]
    CorruptRecord(String),
}

/// Convenience alias for `Result<T, StoreError>`.
pub type StoreResult<T> = Result<T, StoreError>;

/// Builds a [`StoreError::Crypto`] from a failed cryptographic operation.
///
/// `context` names what the operation was for (e.g. `"hashing password"`),
/// so the resulting message explains the failure without the caller
/// repeating it. Kept as its own function, shared by the sqlite and
/// postgres backends, so the error conversion itself can be exercised
/// directly in tests: the operating system's randomness source cannot be
/// forced to fail on demand.
pub(crate) fn crypto_error(context: &str, error: impl std::fmt::Display) -> StoreError {
    StoreError::Crypto(format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::{StoreError, crypto_error};

    #[test]
    fn crypto_error_returns_instead_of_panicking_on_an_ordinary_message() {
        let err = crypto_error("hashing password", "Operation not permitted (os error 1)");
        assert!(matches!(err, StoreError::Crypto(_)));
    }

    #[test]
    fn crypto_error_message_carries_context_and_cause() {
        let err = crypto_error("generating token", "salt too short");
        assert_eq!(
            err.to_string(),
            "crypto error: generating token: salt too short"
        );
    }
}
