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

//! `listunspent`
//!
//! Lists unspent UTXOs in the form of 
//!

use crate::rpc;
use icboc::Dongle;
use miniscript::bitcoin;
use serde::Deserialize;
use std::path::Path;

/// Lists all UTXOs
pub struct ListUnspent;

/// Lists all UTXOs
#[derive(Deserialize)]
pub struct Options {
}

impl super::Command for ListUnspent {
    type Options = Options;

    fn execute<D: Dongle, P: AsRef<Path>>(
        _options: Self::Options,
        wallet_path: P,
        _bitcoind: &rpc::Bitcoind,
        dongle: &mut D,
    ) -> anyhow::Result<()> {
        let (key, _) = super::get_wallet_key_and_nonce(dongle)?;
        let wallet = super::open_wallet(&wallet_path, key)?;

        let mut all_txos = vec![];

        let mut full_balance = 0;
        for (n, _) in wallet.descriptors() {
            let txos = wallet.txos_for(n);
            let mut balance = 0;
            for txo in txos {
                if txo.spending_txid().is_none() {
                    all_txos.push(*txo);
                    balance += txo.value();
                }
            }
            full_balance += balance;
        }
        all_txos.sort();
        for txo in all_txos {
            println!("{}", txo);
        }
        println!("Total balance: {}", bitcoin::Amount::from_sat(full_balance));
        println!("");

        return Ok(());
    }
}

