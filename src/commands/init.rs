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

//! `init`
//!
//! Initializes a new wallet
//!

use anyhow::Context;
use icboc::{Dongle, Wallet};
use serde::Deserialize;
use std::{fs, path::Path};

/// Initialize a new wallet
pub struct Init;

/// Initialize a new wallet
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    #[serde(default)]
    force: bool,
}

impl super::Command for Init {
    type Options = Options;

    fn execute<D: Dongle, P: AsRef<Path>>(
        options: Self::Options,
        wallet_path: P,
        dongle: &mut D,
    ) -> anyhow::Result<()> {
        let wallet_name = wallet_path.as_ref().to_string_lossy().into_owned();

        if fs::metadata(&wallet_path).is_ok() {
            if options.force {
                println!("WARNING: file {} already exists, overwriting.", wallet_name);
            } else {
                println!(
                    "File {} already exists, refusing to overwrite.",
                    wallet_name
                );
                return Err(anyhow::Error::msg(
                    "will not overwrite file with new wallet",
                ));
            }
        }

        let (key, nonce) = super::get_wallet_key_and_nonce(dongle)?;

        let fh = fs::File::create(&wallet_path)?;
        Wallet::new()
            .write(fh, key, nonce)
            .with_context(|| format!("writing blank wallet {}", wallet_name))?;
        println!("Initialized wallet at {}.", wallet_name);
        return Ok(());
    }
}
