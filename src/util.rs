// ICBOC
// Written in 2017 by
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

use base64;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::blockdata::script::Script;
use bitcoin::network::encodable::{ConsensusEncodable, VarInt};
use bitcoin::network::serialize::RawEncoder;
use crypto::digest::Digest;
use crypto::sha2;
use secp256k1::{Secp256k1, ContextFlag, Signature};
use secp256k1::key::SecretKey;

use spend::Spend;
use error::Error;

/// Compute the SHA256 of some slice
pub fn hash_sha256(input: &[u8]) -> [u8; 32] {
    let mut result = [0; 32];
    let mut hasher = sha2::Sha256::new();
    hasher.input(input);
    hasher.result(&mut result);
    result
}

// The returned signature format is a bit funny. It is ASN.1 according to
// the docs, but the first byte, which is uniformly 0x30 (SEQUENCE OF) in
// libsecp, is alternately 0x30 (SEQUENCE OF) or 0x31 (SET OF). Further,
// while s is always encoded in 32 bytes, r is encoded in either 32 or 33,
// depending on which y coordinate this r corresponds to. The docs suggest
// using the parity of the first byte to determine this and to translate
// it into a recovery ID, which is clever and probably the most sensible
// thing to translate this format into Core's `signmessage` format ....
// but is otherwise kinda crazy.
//
// Instead what we do is just pull the 32-byte r and s values out, if r
// was previously 33 byte I'll flip s, and then before verification I'll
// reassemble it into a 70-byte DER signature.
//
// The following two functions do this.

const NEG_ONE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
    0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40
];

/// Parses a signature returned from the Ledger device into a "compact"
/// form which is 32 bytes `r` followed by 32 bytes `s`. Flips `s` if
/// necessary. This does NOT result in BIP66-compliant low-s signatures,
/// it merely makes the public nonce correspond to the encoded `r` value
/// in a consistent way.
///
/// This may panic on bad input.
pub fn convert_ledger_der_to_compact(sig: &[u8]) -> Result<[u8; 64], Error> {
    let r_len = sig[3] as usize;
    let s_len = sig[5 + r_len] as usize;
    let r_off = 4;
    let s_off = 6 + r_len;

    if s_len > 32 || r_len > 33 {
        return Err(Error::BadSignature);
    }

    let mut ret = [0; 64];
    if r_len < 33 {
        // If it's already in a 32r-32s form, awesome, just strip out the ASN.1
        // metadata and maybe pad in some zeroes
        ret[32 - r_len..32].copy_from_slice(&sig[r_off..r_off + r_len]);
        ret[64 - s_len..64].copy_from_slice(&sig[s_off..s_off + s_len]);
    } else {
        assert_eq!(r_len, 33);  // the early return up top ensures this
        // Otherwise there is a nonzero bit in front of r. We have to negate s
        // to make this bit zero, then we can pretend it doesn't exist
        let secp = Secp256k1::with_caps(ContextFlag::None);

        let neg_one = SecretKey::from_slice(&secp, &NEG_ONE).unwrap();
        let mut s_arr = [0; 32];
        s_arr[32 - s_len..32].copy_from_slice(&sig[s_off..s_off + s_len]);
        let mut s_sk = SecretKey::from_slice(&secp, &s_arr)?;
        s_sk.mul_assign(&secp, &neg_one)?;

        ret[0..32].copy_from_slice(&sig[r_off + 1..r_off + r_len]);
        ret[32..64].copy_from_slice(&s_sk[..]);
    }
    Ok(ret)
}

/// Expands a compact-encoded sig into one that can be verified by libsecp
pub fn convert_compact_to_secp(sig: &[u8]) -> Result<Signature, Error> {
    let secp = Secp256k1::with_caps(ContextFlag::None);
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
    // Encode segwit magic
    if !tx.witness.is_empty() {
        encode_marking_cutpoints(&0u8, &mut ret_ser_tx, &mut ret_cuts, max_size);
        encode_marking_cutpoints(&1u8, &mut ret_ser_tx, &mut ret_cuts, max_size);
    }
    // Encode inputs
    encode_marking_cutpoints(&VarInt(tx.input.len() as u64), &mut ret_ser_tx, &mut ret_cuts, max_size);
    for input in &tx.input {
        encode_marking_cutpoints(&input.prev_hash, &mut ret_ser_tx, &mut ret_cuts, max_size);
        ret_cuts.pop();  // Cut between txid and vout disallowed
        encode_marking_cutpoints(&input.prev_index, &mut ret_ser_tx, &mut ret_cuts, max_size);
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
    // Encode witnesses
    if !tx.witness.is_empty() {
        encode_marking_cutpoints(&VarInt(tx.witness.len() as u64), &mut ret_ser_tx, &mut ret_cuts, max_size);
        for witness in &tx.witness {
            // Encode the individual components of the witnesses
            encode_marking_cutpoints(&VarInt(witness.len() as u64), &mut ret_ser_tx, &mut ret_cuts, max_size);
            for component in witness {
                encode_marking_cutpoints(component, &mut ret_ser_tx, &mut ret_cuts, max_size);
            }
        }
    }
    // Finish
    encode_marking_cutpoints(&tx.lock_time, &mut ret_ser_tx, &mut ret_cuts, max_size);

    (ret_ser_tx, ret_cuts)
}

/// Wrapper around `encode_marking_cutpoint` that encodes the inputs of a segwit transaction
/// during the initial call to `UntrustedHashInputStart`
pub fn encode_spend_inputs_with_cutpoints_segwit_init(spend: &Spend, max_size: usize) -> (Vec<u8>, Vec<usize>) {
    let mut ret_ser_tx = vec![];
    let mut ret_cuts = vec![0];  // mark initial cut at 0

    // Encode version
    encode_marking_cutpoints(&1u32, &mut ret_ser_tx, &mut ret_cuts, max_size);
    // Encode inputs
    encode_marking_cutpoints(&VarInt(spend.input.len() as u64), &mut ret_ser_tx, &mut ret_cuts, max_size);
    for input in &spend.input {
        ret_ser_tx.push(0x02); // segwit input to follow
        ret_ser_tx.extend(&input.txin.prev_hash[..]);
        encode_marking_cutpoints(&input.txin.prev_index, &mut ret_ser_tx, &mut ret_cuts, max_size);
        encode_marking_cutpoints(&input.amount, &mut ret_ser_tx, &mut ret_cuts, max_size);
        // script/sequence as in normal bitcoin encoding
        encode_marking_cutpoints(&Script::new(), &mut ret_ser_tx, &mut ret_cuts, max_size);
        encode_marking_cutpoints(&input.txin.sequence, &mut ret_ser_tx, &mut ret_cuts, max_size);
    }
    // Halt here, do not encode number of outputs
    (ret_ser_tx, ret_cuts)
}

/// Like above, but for each input, in subsequent calls to `UntrustedHashInputStart`
pub fn encode_spend_inputs_with_cutpoints_segwit_input(spend: &Spend, index: usize, max_size: usize) -> (Vec<u8>, Vec<usize>) {
    let mut ret_ser_tx = vec![];
    let mut ret_cuts = vec![0];  // mark initial cut at 0

    // Encode version
    encode_marking_cutpoints(&1u32, &mut ret_ser_tx, &mut ret_cuts, max_size);
    // Encode inputs
    encode_marking_cutpoints(&VarInt(1), &mut ret_ser_tx, &mut ret_cuts, max_size);
    for input in &spend.input {
        // Only encode the one input
        if input.index == index {
            ret_ser_tx.push(0x02); // segwit input to follow
            ret_ser_tx.extend(&input.txin.prev_hash[..]);
            encode_marking_cutpoints(&input.txin.prev_index, &mut ret_ser_tx, &mut ret_cuts, max_size);
            encode_marking_cutpoints(&input.amount, &mut ret_ser_tx, &mut ret_cuts, max_size);
            // script/sequence as in normal bitcoin encoding
            encode_marking_cutpoints(&Script::new(), &mut ret_ser_tx, &mut ret_cuts, max_size);
            encode_marking_cutpoints(&input.txin.sequence, &mut ret_ser_tx, &mut ret_cuts, max_size);
        }
    }
    // Halt here, do not encode number of outputs
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

