//! Tiny serde adapters for types whose derive doesn't fire out of the box.
//!
//! Serde's built-in `Serialize`/`Deserialize` impls for `[T; N]` cover up
//! to `N = 32` only — anything wider (in our case, 64-byte Ed25519
//! signatures) needs a custom adapter. Rather than pull in
//! `serde-big-array` for one type, we provide a tiny tuple-style adapter
//! here and reference it via `#[serde(with = "crate::serde_helpers::...")]`
//! at each call site.
//!
//! Output shape:
//! - JSON: a fixed-length array of 64 numbers (since JSON has no bytes
//!   type). Identical to what serde would do for `[u8; 32]`.
//! - CBOR: a fixed-length CBOR array of 64 small ints. Slightly less
//!   compact than `serialize_bytes` would be, but cleanly round-trips
//!   through any serde data format without depending on bytes support.

use std::fmt;

use serde::{
    de::{Deserializer, Error, SeqAccess, Visitor},
    ser::{SerializeTuple, Serializer},
};

/// Adapter for `[u8; 64]`. Use with `#[serde(with = "crate::serde_helpers::serde_arr64")]`.
pub mod serde_arr64 {
    use super::*;

    pub fn serialize<S: Serializer>(arr: &[u8; 64], ser: S) -> Result<S::Ok, S::Error> {
        let mut tup = ser.serialize_tuple(64)?;
        for b in arr.iter() {
            tup.serialize_element(b)?;
        }
        tup.end()
    }

    struct Arr64Visitor;
    impl<'de> Visitor<'de> for Arr64Visitor {
        type Value = [u8; 64];
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a 64-byte array")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut out = [0u8; 64];
            for (i, slot) in out.iter_mut().enumerate() {
                *slot = seq
                    .next_element()?
                    .ok_or_else(|| A::Error::invalid_length(i, &self))?;
            }
            Ok(out)
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 64], D::Error> {
        de.deserialize_tuple(64, Arr64Visitor)
    }
}

/// Adapter for `Option<[u8; 64]>`. Use with `#[serde(with = "crate::serde_helpers::serde_opt_arr64")]`.
/// Pair with `#[serde(default, skip_serializing_if = "Option::is_none")]` to keep on-disk
/// files compact when the field is absent.
pub mod serde_opt_arr64 {
    use super::*;
    use serde::Deserialize;

    pub fn serialize<S: Serializer>(opt: &Option<[u8; 64]>, ser: S) -> Result<S::Ok, S::Error> {
        // Newtype wrapper so the outer `Some(...)` / `None` shape stays a
        // standard `Option`, while the inner 64-byte array is encoded by
        // our tuple adapter.
        #[derive(serde::Serialize)]
        struct W<'a>(#[serde(with = "super::serde_arr64")] &'a [u8; 64]);
        match opt {
            Some(arr) => ser.serialize_some(&W(arr)),
            None => ser.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        de: D,
    ) -> Result<Option<[u8; 64]>, D::Error> {
        #[derive(serde::Deserialize)]
        struct W(#[serde(with = "super::serde_arr64")] [u8; 64]);
        let opt: Option<W> = Option::deserialize(de)?;
        Ok(opt.map(|w| w.0))
    }
}
