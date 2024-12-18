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

use icboc::Dongle;
use miniscript::bitcoin;
use serde::Deserialize;
use std::path::Path;

/// Lists all UTXOs
pub struct ListUnspent;

/// Lists all UTXOs
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    #[serde(default)]
    show_all: bool,
}

impl super::Command for ListUnspent {
    type Options = Options;

    fn execute<D: Dongle, P: AsRef<Path>>(
        options: Self::Options,
        wallet_path: P,
        dongle: &mut D,
    ) -> anyhow::Result<()> {
        let (key, _) = super::get_wallet_key_and_nonce(&mut *dongle)?;
        let wallet = super::open_wallet(&mut *dongle, &wallet_path, key)?;

        let mut all_txos: Vec<_> = wallet.all_txos().collect();
        all_txos.sort();

        let full_balance = all_txos
            .iter()
            .filter(|txo| txo.spent_data.is_none())
            .map(|txo| txo.value)
            .sum::<bitcoin::Amount>();

        for txo in all_txos {
            if options.show_all || txo.spent_data.is_none() {
                println!("{}", txo);
            }
        }
        println!("Total balance: {}", full_balance);
        println!();

        Ok(())
    }
}
