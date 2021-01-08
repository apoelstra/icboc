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

//! `signrawtransaction`
//!
//! Signs a raw transaction where every input is fully owned by the wallet.
//! Also notices which outputs belong to the wallet and interprets them as
//! change.
//!

use crate::rpc;
use anyhow::Context;
use icboc::Dongle;
use miniscript::bitcoin::{self, consensus, hashes::hex::FromHex};
use serde::Deserialize;
use std::path::Path;

/// Signs a raw transaction
pub struct SignRawTransaction;

/// Signs a raw transaction
#[derive(Deserialize)]
pub struct Options {
    /// Hex-encoded transaction to sign
    tx: String,
}

impl super::Command for SignRawTransaction {
    type Options = Options;

    fn execute<D: Dongle, P: AsRef<Path>>(
        options: Self::Options,
        wallet_path: P,
        _bitcoind: &rpc::Bitcoind,
        dongle: &mut D,
    ) -> anyhow::Result<()> {
        let (key, _) = super::get_wallet_key_and_nonce(dongle)?;
        let wallet = super::open_wallet(&mut *dongle, &wallet_path, key)?;

        let rawtx = Vec::<u8>::from_hex(&options.tx).context("hex-decoding raw transaction")?;
        let tx: bitcoin::Transaction =
            consensus::deserialize(&rawtx).context("decoding raw transaction")?;

        for input in &tx.input {
            let txo = wallet
                .txo(input.previous_output)
                .with_context(|| format!("looking up {} in wallet", input.previous_output))?;
            println!("input: {}", txo);
            let tx = wallet.tx(input.previous_output.txid).with_context(|| {
                format!("looking up {} in tx cache", input.previous_output.txid)
            })?;
            let trusted_input = dongle
                .get_trusted_input(&tx, input.previous_output.vout)
                .with_context(|| {
                    format!(
                        "asking the the dongle for a trusted input for {}",
                        input.previous_output
                    )
                })?;
            println!("trusted input: {:?}", trusted_input);
        }

        for output in &tx.output {
            if let Some(addr) = wallet.address_from_spk(&output.script_pubkey) {
                println!("change: {}", addr);
            }
        }

        return Ok(());
    }
}
