// ICBOC 3D
// Written in 2020 by
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

//! # Miscellaneous Functions

use miniscript::bitcoin::secp256k1;
use miniscript::bitcoin::secp256k1::recovery::{RecoverableSignature, RecoveryId};
/*
use base64;
use bitcoin::{Transaction, Script, VarInt};
use bitcoin::network::encodable::ConsensusEncodable;
use bitcoin::network::serialize::RawEncoder;
use crypto::digest::Digest;
use crypto::sha2;
use secp256k1::{Secp256k1, Signature, SecretKey};

use spend::Spend;
use error::Error;
*/

/*
/// Compute the SHA256 of some slice
pub fn hash_sha256(input: &[u8]) -> [u8; 32] {
    let mut result = [0; 32];
    let mut hasher = sha2::Sha256::new();
    hasher.input(input);
    hasher.result(&mut result);
    result
}
*/

/// Parse a Ledger-encoded signmessage signature
///
/// May edit the passed signature in place. Make a copy if you need to preserve
/// it for some reason.
///
/// The Ledger signature format is a bit funny. It is ASN.1 according to
/// the docs, but the first byte, which is uniformly 0x30 (SEQUENCE OF) in
/// DER, is alternately 0x30 (SEQUENCE OF) or 0x31 (SET OF). Further, while
/// s is always encoded in 32 bytes (in DER it may be variable), r is encoded
/// in either 32 or 33, depending on which y coordinate this r corresponds
/// (also varable, and signed to boot).
/// The docs suggest using the parity of the first byte to determine this
/// and to translate it into a recovery ID, which is clever I suppose, but
/// not DER (and barely ASN.1).
///
/// Anyway, to parse these, the most straightforward thing is to pull the
/// recid out of the 30/31 byte as suggested, then force the byte to 0x30
/// and parse using from_der_lax.
pub fn parse_ledger_signature_recoverable(sig: &mut [u8]) -> Result<RecoverableSignature, secp256k1::Error> {
    // Check recid
    let recid = if !sig.is_empty() && sig[0] == 0x31 {
        sig[0] = 0x30;
        RecoveryId::from_i32(1).unwrap()
    } else {
        RecoveryId::from_i32(0).unwrap()
    };
    let sig = secp256k1::Signature::from_der_lax(sig)?;
    RecoverableSignature::from_compact(&sig.serialize_compact(), recid)
}

/// Same as `parse_ledger_signature_recoverable` but don't bother with the recovery id
pub fn parse_ledger_signature(sig: &mut [u8]) -> Result<secp256k1::Signature, secp256k1::Error> {
    if !sig.is_empty() && sig[0] == 0x31 {
        sig[0] = 0x30;
    }
    secp256k1::Signature::from_der_lax(sig)
}

/*
/// Expands a compact-encoded sig into one that can be verified by libsecp
pub fn convert_compact_to_secp(sig: &[u8]) -> Result<Signature, Error> {
    let secp = Secp256k1::without_caps();
    let mut rv = [0; 70];
    rv[0] = 0x30; // Sequence
    rv[1] = 0x44; // length of remainder
    rv[2] = 0x02; // Integer (r)
    rv[3] = 0x20; // Length of Integer (r)
    rv[4..36].copy_from_slice(&sig[0..32]);  // r
    rv[36] = 0x02; // Integer (s)
    rv[37] = 0x20; // Length of Integer (s)
    rv[38..70].copy_from_slice(&sig[32..64]);  // s
    let mut sig = Signature::from_der_lax(&secp, &rv)?;
    sig.normalize_s(&secp);
    Ok(sig)
}

/// Converts a compact-encoded signature into a base64-encoded string that
/// can be verified by the `verifymessage` RPC in Bitcoin Core
pub fn convert_compact_to_signmessage_rpc(sig: &[u8]) -> Result<String, Error> {
    // Our "compact encoding" in fact exactly matches that of a libsecp compact sig
    // with recovery ID zero, so we simply prepend a 31 and base-64 encode it.
    let mut ret = vec![31u8];
    ret.extend(sig);
    Ok(base64::encode(&ret))
}

/// Transactions are sent to the device in a bit of a weird way. Each individual
/// transaction component needs to be sent to the device intact (except possibly
/// scripts), but any transaction will greatly exceed the APDU packet size (260
/// bytes minus whatever header data is needed). So we need to carefully split
/// the transaction being sure not to cut any primitives except for scripts.
///
/// What this function does is encodes a primitive, marking a cut-point before
/// and after it (and within, if it is too long -- scripts are the only thing
/// that will do this, so this is ok). We leave it to a higher layer to use an
/// optimal set of cut-points.
///
/// Cut-points are encoded as indices into the data array, including 0 and the
/// total length.
fn encode_marking_cutpoints<'a, T>(data: &T, buf: &'a mut Vec<u8>, cuts: &mut Vec<usize>, max_size: usize)
    where T: ConsensusEncodable<RawEncoder<&'a mut Vec<u8>>>
{
    // Encode
    let mut encoder = RawEncoder::new(buf);
    data.consensus_encode(&mut encoder).unwrap();
    let buf = encoder.into_inner();

    // Record any required cuts partway through the data
    let mut last_cut = *cuts.last().unwrap();
    while buf.len() > last_cut + max_size {
        cuts.push(last_cut + max_size);
        last_cut = *cuts.last().unwrap();
    }
    // Record cut at end of encoding (this could duplicate a cut from the
    // above loop, but that's fine, 0-length cuts are harmless).
    cuts.push(buf.len());
}

/// Wrapper around `encode_marking_cutpoint` that encodes a Transaction correctly
pub fn encode_transaction_with_cutpoints(tx: &Transaction, max_size: usize) -> (Vec<u8>, Vec<usize>) {
    let mut ret_ser_tx = vec![];
    let mut ret_cuts = vec![0];  // mark initial cut at 0

    // Copied structure from rust-bitcoin transaction.rs, with TxIn and TxOut unrolled
    encode_marking_cutpoints(&tx.version, &mut ret_ser_tx, &mut ret_cuts, max_size);
    encode_marking_cutpoints(&VarInt(tx.input.len() as u64), &mut ret_ser_tx, &mut ret_cuts, max_size);
    for input in &tx.input {
        encode_marking_cutpoints(&input.previous_output.txid, &mut ret_ser_tx, &mut ret_cuts, max_size);
        ret_cuts.pop();  // Cut between txid and vout disallowed
        encode_marking_cutpoints(&input.previous_output.vout, &mut ret_ser_tx, &mut ret_cuts, max_size);
        ret_cuts.pop();  // Ditto between vout and script_sig length
        encode_marking_cutpoints(&input.script_sig, &mut ret_ser_tx, &mut ret_cuts, max_size);
        encode_marking_cutpoints(&input.sequence, &mut ret_ser_tx, &mut ret_cuts, max_size);
    }
    // Encode outputs
    encode_marking_cutpoints(&VarInt(tx.output.len() as u64), &mut ret_ser_tx, &mut ret_cuts, max_size);
    for output in &tx.output {
        encode_marking_cutpoints(&output.value, &mut ret_ser_tx, &mut ret_cuts, max_size);
        ret_cuts.pop();  // Cut between value and script_pubkey disallowed
        encode_marking_cutpoints(&output.script_pubkey, &mut ret_ser_tx, &mut ret_cuts, max_size);
    }
    // Do not encode witnesses; these are not used when sending transactions to the Ledger
    // Finish
    encode_marking_cutpoints(&tx.lock_time, &mut ret_ser_tx, &mut ret_cuts, max_size);

    (ret_ser_tx, ret_cuts)
}

/// Wrapper around `encode_marking_cutpoint` that encodes a Spend's inputs correctly
/// No segwit support
pub fn encode_spend_inputs_with_cutpoints(spend: &Spend, index: usize, max_size: usize) -> (Vec<u8>, Vec<usize>) {
    let mut ret_ser_tx = vec![];
    let mut ret_cuts = vec![0];  // mark initial cut at 0

    // This is quite different from the Bitcoin format as we have to replace some
    // things with flags to encode inputs using the dongle's "Trusted Inputs"
    // Encode version
    encode_marking_cutpoints(&1u32, &mut ret_ser_tx, &mut ret_cuts, max_size);
    // Encode inputs
    encode_marking_cutpoints(&VarInt(spend.input.len() as u64), &mut ret_ser_tx, &mut ret_cuts, max_size);
    for input in &spend.input {
        ret_ser_tx.push(0x01); // trusted input to follow
        ret_ser_tx.push(input.trusted_input.len() as u8);
        ret_ser_tx.extend(&input.trusted_input[..]);
        if input.index == index {
            encode_marking_cutpoints(&input.script_pubkey, &mut ret_ser_tx, &mut ret_cuts, max_size);
        } else {
            encode_marking_cutpoints(&Script::new(), &mut ret_ser_tx, &mut ret_cuts, max_size);
        }
        encode_marking_cutpoints(&input.txin.sequence, &mut ret_ser_tx, &mut ret_cuts, max_size);
    }
    // Halt here, do not encode number of outputs
    (ret_ser_tx, ret_cuts)
}

/// Wrapper around `encode_marking_cutpoint` that encodes a Spend's outputs correctly
pub fn encode_spend_outputs_with_cutpoints(spend: &Spend, max_size: usize) -> (Vec<u8>, Vec<usize>) {
    let mut ret_ser_tx = vec![];
    let mut ret_cuts = vec![0];  // mark initial cut at 0

    // Encode outputs
    encode_marking_cutpoints(&VarInt(spend.output.len() as u64), &mut ret_ser_tx, &mut ret_cuts, max_size);
    for output in &spend.output {
        encode_marking_cutpoints(&output.value, &mut ret_ser_tx, &mut ret_cuts, max_size);
        ret_cuts.pop();  // Cut between value and script_pubkey disallowed
        encode_marking_cutpoints(&output.script_pubkey, &mut ret_ser_tx, &mut ret_cuts, max_size);
    }
    // Halt here, do not encode number of outputs
    (ret_ser_tx, ret_cuts)
}

*/



