use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
  #[error("hash not found")]
  HashNotFound,
  #[error("peer not found")]
  PeerNotFound,
  #[cfg(feature = "sql")]
  #[error("error with rusqlite")]
  SQLite(#[from] rusqlite::Error),
  #[cfg(feature = "sql")]
  #[error("error with rusqlite_migrations")]
  SQLiteMigration(#[from] rusqlite_migration::Error),
}
