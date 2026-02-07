

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));


/// Safe Rust wrapper for xDL
///
/// This module provides a safe, idiomatic Rust API for xDL.
/// Use this instead of the raw FFI bindings when possible.
pub mod safe;

