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

//! `importdescriptor`
//!
//! Imports a (ranged) descriptor into the wallet
//!

use anyhow::Context;
use icboc::Dongle;
use miniscript::{Descriptor, DescriptorPublicKey};
use serde::Deserialize;
use std::path::Path;

/// Gets information
pub struct ImportDescriptor;

/// Gets information
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    desc: Descriptor<DescriptorPublicKey>,
    #[serde(default)]
    range_low: Option<u32>,
    #[serde(default)]
    range_high: Option<u32>,
}

impl super::Command for ImportDescriptor {
    type Options = Options;

    fn execute<D: Dongle, P: AsRef<Path>>(
        options: Self::Options,
        wallet_path: P,
        dongle: &mut D,
    ) -> anyhow::Result<()> {
        let (key, nonce) = super::get_wallet_key_and_nonce(dongle)?;
        let mut wallet = super::open_wallet(&mut *dongle, &wallet_path, key)?;

        let range = match (options.range_low, options.range_high) {
            (None, None) => 0..101,
            (Some(lo), None) => lo..101,
            (Some(lo), Some(hi)) => lo..hi + 1,
            (None, Some(hi)) => 0..hi + 1,
        };
        if range.start >= range.end {
            return Err(anyhow::Error::msg(format!("invalid range {:?}", range)));
        }

        println!(
            "Asked to import descriptor {}. Generating addresses from {} through {}",
            options.desc,
            range.start,
            range.end - 1,
        );
        let n_added = wallet
            .add_descriptor(options.desc, range.start, range.end, &mut *dongle)
            .with_context(|| "importing descriptor")?;

        if n_added == 0 {
            println!(
                "Wallet already has all keys from {} through {}.",
                range.start,
                range.end - 1
            );
            return Err(anyhow::Error::msg("nothing to do"));
        }
        println!(
            "Imported {} new addresses. You should now call `rescan`.",
            n_added
        );

        super::save_wallet(&wallet, wallet_path, key, nonce)
            .with_context(|| format!("saving wallet after import"))?;

        return Ok(());
    }
}
