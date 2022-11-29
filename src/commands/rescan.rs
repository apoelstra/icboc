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
//! Scans the blockchain for new transactions
//!

#![cfg_attr(not(feature = "jsonrpc"), allow(dead_code))]
#![cfg_attr(not(feature = "jsonrpc"), allow(unused_imports))]

#[cfg(feature = "jsonrpc")]
use crate::rpc;
use anyhow::Context;
use icboc::Dongle;
use serde::Deserialize;
use std::path::Path;

/// Scans the blockchain for new transactions
pub struct Rescan;

fn default_timeout() -> u64 {
    1000
}

/// Scans the blockchain for new transactions
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    start_from: Option<u64>,
    #[serde(default = "default_timeout")]
    timeout_ms: u64,
}

#[cfg(not(feature = "jsonrpc"))]
impl super::Command for Rescan {
    type Options = Options;

    fn execute<D: Dongle, P: AsRef<Path>>(_: Options, _: P, _: &mut D) -> anyhow::Result<()> {
        Err(anyhow::Error::msg(
            "you must compile this crate with the jsonrpc feature to get the 'rescan' command",
        ))
    }
}

#[cfg(feature = "jsonrpc")]
impl super::Command for Rescan {
    type Options = Options;

    fn execute<D: Dongle, P: AsRef<Path>>(
        options: Self::Options,
        wallet_path: P,
        dongle: &mut D,
    ) -> anyhow::Result<()> {
        let bitcoind = rpc::Bitcoind::connect("~/.bitcoin/.cookie", options.timeout_ms)?;
        let n = bitcoind.getblockcount()?;
        println!("Connected to bitcoind. Block count: {}", n);

        let (key, nonce) = super::get_wallet_key_and_nonce(dongle)?;
        let mut wallet = super::open_wallet(&mut *dongle, &wallet_path, key)?;

        let mut height = options
            .start_from
            .unwrap_or(wallet.block_height().saturating_sub(100));
        let mut max_height = bitcoind
            .getblockcount()
            .context("getting initial block count")?;

        println!(
            "Scanning from block {}. Current height: {}",
            height, max_height
        );
        while height < max_height {
            let block = bitcoind
                .getblock(height)
                .with_context(|| format!("fetching block {}", height))?;

            if height > 0 && height % 1000 == 0 {
                wallet.set_block_height(height);
                super::save_wallet(&wallet, &wallet_path, key, nonce)
                    .with_context(|| format!("saving wallet at height {}", height))?;
                println!(
                    "Height {:7}: {} {:?}",
                    height,
                    block.block_hash(),
                    std::time::Instant::now()
                );
            }

            let (received, spent) = wallet.scan_block(&block, height);
            for txo in spent {
                println!("spent {}", txo);
            }
            for txo in received {
                println!("received {}", wallet.txo(txo).unwrap());
            }

            height += 1;
            if height == max_height {
                max_height = bitcoind.getblockcount().context("getting block count")?;
            }
        }
        wallet.set_block_height(height);

        super::save_wallet(&wallet, &wallet_path, key, nonce)
            .with_context(|| format!("saving wallet at height {}", height))?;

        return Ok(());
    }
}
