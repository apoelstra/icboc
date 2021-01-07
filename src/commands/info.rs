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

//! `info`
//!
//! Gets information about data stored by the wallet
//!

use anyhow::Context;
use crate::rpc;
use icboc::Dongle;
use miniscript::bitcoin;
use serde::Deserialize;
use std::path::Path;

/// Gets information
pub struct Info;

/// Gets information
#[derive(Deserialize)]
pub struct Options {
    #[serde(default)]
    descriptors: Vec<usize>,
    #[serde(default)]
    txos: Vec<bitcoin::OutPoint>,
}

impl super::Command for Info {
    type Options = Options;

    fn execute<D: Dongle, P: AsRef<Path>>(
        options: Self::Options,
        wallet_path: P,
        _bitcoind: &rpc::Bitcoind,
        dongle: &mut D,
    ) -> anyhow::Result<()> {
        let (key, _) = super::get_wallet_key_and_nonce(dongle)?;
        let wallet = super::open_wallet(&wallet_path, key)?;

        let mut full_balance = 0;
        if !wallet.descriptors.is_empty() {
            println!("Descriptors:");
            for (n, desc) in wallet.descriptors() {
                let txos = wallet.txos_for(n);
                let mut n_spent = 0;
                let mut balance = 0;
                for txo in &txos {
                    if txo.spending_txid().is_some() {
                        n_spent += 1;
                    } else {
                        balance += txo.value();
                    }
                }
                println!("  {:4} {}", n, desc.desc);
                println!("       Range: {}-{}", desc.low, desc.high - 1);
                println!("       TXOs: {} total, {} spent", txos.len(), n_spent);
                println!("       Balance: {}", bitcoin::Amount::from_sat(balance));
                println!("");
                full_balance += balance;
            }
        }
        let mut addresses = Vec::with_capacity(wallet.addresses.len());
        for addr in wallet.addresses.values() {
            let addr = addr.info(&wallet, &mut *dongle)
                .context("looking up address info")?;
            addresses.push(addr);
        }
        if !addresses.is_empty() {
            addresses.sort();
            for addr in &addresses {
                println!("{}", addr);
            }
            println!("");
        }
        println!("Last rescan to: {}.", wallet.block_height);
        println!("Wallet balance: {}", bitcoin::Amount::from_sat(full_balance));
        println!("");

        return Ok(());
    }
}

