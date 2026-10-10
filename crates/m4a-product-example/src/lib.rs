//! The example product server: library surface (router + store) so a real
//! product can reuse or replace each piece, and tests can run it in-process.

pub mod app;
pub mod store;

pub use app::{router, ProductApp};
pub use store::SqliteStore;
