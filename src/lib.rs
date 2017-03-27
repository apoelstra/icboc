// IceBox
// Written in 2017 by
//   Andrew Poelstra <icebox@wpsoftware.net>
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
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(missing_docs)]

extern crate byteorder;
extern crate crypto;
#[macro_use] extern crate log;
extern crate hex;
extern crate hid;
extern crate secp256k1;
extern crate time;

pub mod constants;
pub mod dongle;
pub mod error;
pub mod util;
pub mod wallet;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
