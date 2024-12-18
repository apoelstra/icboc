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

//! `rescan`
//!
//! Accepts a single transaction
//!

use anyhow::Context;
use icboc::Dongle;
use miniscript::bitcoin::{self, consensus, hashes::hex::FromHex};
use serde::Deserialize;
use std::path::Path;

/// Accept a single transaction
pub struct Receive;

/// Accept a single transaction
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    /// Hex-encoded transaction to receive
    tx: String,
}

impl super::Command for Receive {
    type Options = Options;

    fn execute<D: Dongle, P: AsRef<Path>>(
        options: Self::Options,
        wallet_path: P,
        dongle: &mut D,
    ) -> anyhow::Result<()> {
        let (key, nonce) = super::get_wallet_key_and_nonce(dongle)?;
        let mut wallet = super::open_wallet(&mut *dongle, &wallet_path, key)?;

        let rawtx = Vec::<u8>::from_hex(&options.tx).context("hex-decoding raw transaction")?;
        let tx: bitcoin::Transaction =
            consensus::deserialize(&rawtx).context("decoding raw transaction")?;

        println!("Scanning tx {}", tx.compute_txid());
        let (received, spent) = wallet.scan_tx(&tx, 0);
        for txo in spent {
            println!("spent {}", txo);
        }
        for txo in received {
            println!("received {}", wallet.txo(txo).unwrap());
        }

        super::save_wallet(&wallet, &wallet_path, key, nonce)
            .with_context(|| format!("saving wallet at after receive of {}", tx.compute_txid()))?;

        Ok(())
    }
}
