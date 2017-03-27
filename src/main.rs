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

//! # Ice Box
//!
//! Ice Box is an application/library designed to use the Ledger Nano S
//! (and possibly other Ledger products) in a cold-wallet fashion. That
//! is, it does not interact with any other servers or networks, and is
//! meticulous about logging and timestamping all activity, warning about
//! unsafe usage (e.g. address reuse), and more TBD.
//!

extern crate env_logger;
extern crate icebox;

use icebox::dongle::Dongle;
use icebox::error::Error;
use icebox::constants::apdu::ledger::sw;

fn main() {
    env_logger::init().unwrap();

    let mut dongle = match icebox::dongle::ledger::get_unique() {
        Ok(d) => d,
        Err(e) => {
            panic!("Failed to get device handle: {}", e);
        }
    };

    println!("Successfully found unique device: {:?}", dongle.product());
    
    let version = match dongle.get_firmware_version() {
        Ok(version) => version,
        Err(Error::ApduBadStatus(sw::INS_NOT_SUPPORTED)) => {
            panic!("Device did not understand 'get firmware'. Are you running the BTC app?");
        }
        Err(e) => panic!("Failed to get firmware version: {}", e)
    };

    println!("Firmware version {}.{}.{}", version.major_version, version.minor_version, version.patch_version);
}

