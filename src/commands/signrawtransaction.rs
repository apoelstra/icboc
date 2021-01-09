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
use icboc::{self, Dongle};
use miniscript::bitcoin::{self, consensus, hashes::hex::FromHex};
use miniscript::DescriptorTrait;
use serde::Deserialize;
use std::cell::RefCell;
use std::path::Path;

/// Signs a raw transaction
pub struct SignRawTransaction;

/// Signs a raw transaction
#[derive(Deserialize)]
pub struct Options {
    /// Hex-encoded transaction to sign
    tx: String,
    /// If the transaction has multiple change outputs, the user has to
    /// pick one to make the Ledger happy
    #[serde(default)]
    change_index: Option<usize>,
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
        let mut tx: bitcoin::Transaction =
            consensus::deserialize(&rawtx).context("decoding raw transaction")?;

        let mut change = None;
        if let Some(change_idx) = options.change_index {
            if change_idx >= tx.output.len() {
                return Err(anyhow::Error::msg(format!(
                    "provided change index {} but the transaction has only {} outputs",
                    change_idx,
                    tx.output.len(),
                )));
            }
            change = wallet.address_from_spk(&tx.output[change_idx].script_pubkey);
            if change.is_none() {
                return Err(anyhow::Error::msg(format!(
                    "provided change index {} which the wallet does not recognize",
                    change_idx,
                )));
            }
        } else {
            for output in &tx.output {
                if let Some(addr) = wallet.address_from_spk(&output.script_pubkey) {
                    if change.replace(addr).is_some() {
                        return Err(anyhow::Error::msg("multiple change outputs found; please add 'change_indx' field to disambiguate"));
                    }
                }
            }
        }

        // Sign
        let unsigned_tx = tx.clone();
        let mut satisfier = Satisfier {
            tx: &unsigned_tx,
            input_idx: 0,
            prev_tx: &unsigned_tx,
            dongle: RefCell::new(dongle),
            change_address: change,
        };
        for (n, input) in tx.input.iter_mut().enumerate() {
            satisfier.input_idx = n;
            satisfier.prev_tx = wallet
                .tx(input.previous_output.txid)
                .with_context(|| format!("looking prevtx {} in wallet", input.previous_output))?;

            let txo = wallet
                .txo(input.previous_output)
                .with_context(|| format!("looking up {} in wallet", input.previous_output))?;
            let (wit, script_sig) = txo
                .address
                .instantiated_descriptor
                .get_satisfaction(&satisfier)
                .with_context(|| format!("satisfying input {}", n))?;

            input.script_sig = script_sig;
            input.witness = wit;
        }

        println!(
            "Signed tx: {}",
            bitcoin::consensus::encode::serialize_hex(&tx)
        );
        println!("If you intend to broadcast this transaction you should likely run the 'receive' command with it.");

        return Ok(());
    }
}

struct Satisfier<'tx, 'd, 'c, D> {
    tx: &'tx bitcoin::Transaction,
    prev_tx: &'c bitcoin::Transaction,
    input_idx: usize,
    dongle: RefCell<&'d mut D>,
    change_address: Option<&'c icboc::Address>,
}

impl<'tx, 'd, 'c, D: Dongle> miniscript::Satisfier<icboc::CachedKey> for Satisfier<'tx, 'd, 'c, D> {
    fn lookup_sig(&self, pk: &icboc::CachedKey) -> Option<miniscript::BitcoinSig> {
        let mut dongle = self.dongle.borrow_mut();
        let trusted_input = dongle
            .get_trusted_input(
                self.prev_tx,
                self.tx.input[self.input_idx].previous_output.vout,
            )
            .map_err(|e| {
                println!("getting trusted input: {}", e);
                e
            })
            .ok()?;
        dongle
            .transaction_input_start(self.tx, self.input_idx, &trusted_input)
            .ok()?;
        dongle
            .transaction_input_finalize(self.tx, self.change_address)
            .ok()?;
        dongle
            .transaction_sign(
                &pk.desc_key.full_derivation_path(),
                bitcoin::SigHashType::All,
                self.tx.lock_time,
            )
            .ok()
            .map(|sig| (sig, bitcoin::SigHashType::All))
    }

    fn lookup_pkh_pk(&self, pk: &icboc::CachedKey) -> Option<icboc::CachedKey> {
        Some(pk.clone())
    }

    fn lookup_pkh_sig(
        &self,
        pk: &icboc::CachedKey,
    ) -> Option<(bitcoin::PublicKey, miniscript::BitcoinSig)> {
        self.lookup_sig(pk).map(|sig| (pk.key, sig))
    }
}
