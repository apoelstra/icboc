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

//! # Ice Box
//!
//! Ice Box is an application/library designed to use the Ledger Nano S
//! (and possibly other Ledger products) in a cold-wallet fashion. That
//! is, it does not interact with any other servers or networks, and is
//! meticulous about logging and timestamping all activity, warning about
//! unsafe usage (e.g. address reuse), and more TBD.
//!

use anyhow::Context;
use icboc::Dongle;

mod commands;
#[cfg(feature = "jsonrpc")]
mod rpc;

/// Entry point
fn main() -> anyhow::Result<()> {
    // Contact device and run GET FIRMWARE to sanity check it
    let hid_api = icboc::hid::Api::new().context("getting HID API context")?;
    let mut dongle = icboc::ledger::NanoS::get(&hid_api).context("finding dongle")?;
    let version = dongle
        .get_firmware_version()
        .context("getting app version")?;
    let master_xpub = dongle.get_master_xpub().context("getting master xpub")?;
    println!("Found dongle.");
    println!(
        "    Bitcoin app version {}.{}.{}",
        version.major_version, version.minor_version, version.patch_version
    );
    println!("    Master xpub: {}", master_xpub);
    println!("    Master fingerprint: {}", master_xpub.fingerprint());

    // Do the user's bidding
    commands::execute_from_args(&mut dongle)?;

    Ok(())
}
