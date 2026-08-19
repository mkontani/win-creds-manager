//! Portable core of `wcm`: vault format, crypto, key slots and items.
//!
//! This crate performs no I/O prompts and never calls `process::exit`.
#![forbid(unsafe_code)]

pub mod crypto;
pub mod error;
pub mod slot;

pub use error::{Error, Result};
