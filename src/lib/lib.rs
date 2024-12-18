// ICBOC 3D
// Written in 2021 by
//   Andrew Poelstra <icboc@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Ice Box Library
//!
//! Ice Box is an library designed to use the Ledger Nano S (and possibly
//! other Ledger products) in a cold-wallet fashion. It is the library
//! providing the functionality for the Ice Box application, which can be
//! used directly to interact with the Ledger.
//!

// Coding conventions
#![warn(non_ascii_idents)]
#![warn(non_upper_case_globals)]
#![warn(non_camel_case_types)]
#![warn(non_snake_case)]
#![warn(unused_mut)]
#![warn(missing_docs)]

pub mod constants;
mod dongle;
mod error;
mod util;
mod wallet;

use miniscript::bitcoin::{bip32, secp256k1};
use miniscript::DescriptorPublicKey;
use std::collections::HashMap;

pub use dongle::ledger;
pub use dongle::{Dongle, TrustedInput};
pub use error::Error;
pub use util::{parse_ledger_signature, parse_ledger_signature_recoverable};
pub use wallet::{Address, CachedKey, Descriptor, Txo, Wallet};

// Re-export all the hidapi types because the double `hidapi::HidDevice`
// naming bugs me
/// Re-exports of types from `hidapi` with nicer names
pub mod hid {
    pub use hidapi::HidApi as Api;
    pub use hidapi::HidDevice as Device;
    pub use hidapi::HidError as Error;
}

/// Opaque cache of keys we've queried a dongle for
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyCache {
    map: HashMap<bip32::ExtendedPubKey, HashMap<bip32::DerivationPath, secp256k1::PublicKey>>,
}

impl KeyCache {
    /// Construct a new empty key cache
    fn new() -> Self {
        Self::default()
    }

    /// Looks up a descriptor public key in the cache.
    fn lookup_descriptor_pubkey(
        &self,
        d: &miniscript::DefiniteDescriptorKey,
    ) -> Option<secp256k1::PublicKey> {
        match *d.as_descriptor_public_key() {
            DescriptorPublicKey::Single(ref single) => match single.key {
                miniscript::descriptor::SinglePubKey::FullKey(key) => Some(key.inner),
                miniscript::descriptor::SinglePubKey::XOnly(_) => todo!("No taproot support yet"),
            },
            DescriptorPublicKey::XPub(ref xpub) => self.lookup(xpub.xkey, &xpub.derivation_path),
            DescriptorPublicKey::MultiXPub(..) => panic!("multi-xpubs (BIP 389) not supported"),
        }
    }

    /// Looks up a key in the map
    fn lookup(
        &self,
        xpub: bip32::ExtendedPubKey,
        path: &bip32::DerivationPath,
    ) -> Option<secp256k1::PublicKey> {
        self.map.get(&xpub).and_then(|map| map.get(path)).copied()
    }

    /// Adds a key to the map
    fn insert(
        &mut self,
        xpub: bip32::ExtendedPubKey,
        path: bip32::DerivationPath,
        key: secp256k1::PublicKey,
    ) {
        self.map.entry(xpub).or_default().insert(path, key);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
