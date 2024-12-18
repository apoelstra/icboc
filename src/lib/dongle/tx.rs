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

//! Nano S Transaction Encodings
//!
//! Utility functions to send large amounts of data to the Ledger,
//! in USB sized chunks, only splitting it at allowable locations,
//! where "allowable" is defined by the Nano S Bitcoin App source
//! code.
//!

use std::io;

use crate::dongle::TrustedInput;
use miniscript::bitcoin;
use miniscript::bitcoin::consensus::Encodable;

/// Helper function to turn a usize into a [`bitcoin::VarInt`] for encoding
fn varint(n: usize) -> bitcoin::VarInt {
    bitcoin::VarInt(n as u64)
}

/// Encode a single hunk of data into a multi-part message
///
/// If `obj` can be encoded onto `current_piece` without increasing its
/// length past `piece_len`, do this and return `current_piece`.
///
/// Otherwise, push `current_piece` onto `pieces`, create a fresh vector
/// and encode into that. Return the fresh vector. If the fresh vector's
/// length exceeds `piece_len`, which may happen for Scripts, split it
/// into at-most `piece_len`-sized parts, pushing all but the last onto
/// `pieces`, and return the last one.
pub fn encode<T: Encodable>(
    obj: &T,
    mut current_piece: Vec<u8>,
    pieces: &mut Vec<Vec<u8>>,
    piece_len: usize,
) -> Vec<u8> {
    // Compute the new object's length
    let len = obj.consensus_encode(&mut io::sink()).unwrap();
    // Start a new piece if necessary
    if current_piece.len() + len > piece_len {
        pieces.push(current_piece);
        current_piece = Vec::with_capacity(len);
    }
    // Encode the new object
    obj.consensus_encode(&mut current_piece).unwrap();
    // If this put us over the limit, split it further
    if current_piece.len() > piece_len {
        pieces.extend(current_piece.chunks(piece_len).map(<[u8]>::to_owned));
        current_piece = pieces.pop().unwrap();
    }
    // Return final fragment
    current_piece
}

/// Encode a transaction in pieces
pub fn encode_tx(tx: &bitcoin::Transaction, piece_len: usize) -> Vec<Vec<u8>> {
    let mut ret = vec![];
    let mut cur = Vec::with_capacity(piece_len);
    cur = encode(&tx.version, cur, &mut ret, piece_len);
    cur = encode(&varint(tx.input.len()), cur, &mut ret, piece_len);
    for input in &tx.input {
        // When encoding inputs, we are not allowed to split within the
        // outpoint or before the scriptSig. So we encode those as a
        // single chunk, followed by the sequence.
        cur = encode(
            &(input.previous_output, &input.script_sig),
            cur,
            &mut ret,
            piece_len,
        );
        cur = encode(&input.sequence, cur, &mut ret, piece_len);
    }
    cur = encode(&varint(tx.output.len()), cur, &mut ret, piece_len);
    for output in &tx.output {
        cur = encode(output, cur, &mut ret, piece_len);
    }
    cur = encode(&tx.lock_time, cur, &mut ret, piece_len);
    if !cur.is_empty() {
        ret.push(cur);
    }
    ret
}

/// Encode an input for signing
///
/// This essentially encodes the first half of a transaction (up to the outputs)
/// but in a sorta-ad-hoc way which corresponds to the sighash encoding, which
/// the Ledger is constructing internally
pub fn encode_input(
    tx: &bitcoin::Transaction,
    index: usize,
    trusted_inputs: &[TrustedInput],
    piece_len: usize,
) -> Vec<Vec<u8>> {
    let mut ret = vec![];
    let mut cur = Vec::with_capacity(piece_len);
    cur = encode(&tx.version, cur, &mut ret, piece_len);
    cur = encode(&varint(tx.input.len()), cur, &mut ret, piece_len);
    for (n, input) in tx.input.iter().enumerate() {
        let dummy = bitcoin::ScriptBuf::new();
        let spk = if n == index {
            &trusted_inputs[n].script_pubkey
        } else {
            &dummy
        };
        cur = encode(
            // 1u8 is a "legacy" flag, i.e. trusted input to follow
            // TODO check if we have a segwit spk and use its value instead
            &(
                1u8,
                trusted_inputs[n].blob.to_vec(), // Encodable not implemented on &[u8]
                spk,
            ),
            cur,
            &mut ret,
            piece_len,
        );
        cur = encode(&input.sequence, cur, &mut ret, piece_len);
    }
    // Stop here; vout and lock_time happen in the next messages
    if !cur.is_empty() {
        ret.push(cur);
    }
    ret
}

/// Encodes transaction outputs for signing
///
/// Encodes the second half of a transaction
pub fn encode_outputs(tx: &bitcoin::Transaction, piece_len: usize) -> Vec<Vec<u8>> {
    let mut ret = vec![];
    let mut cur = Vec::with_capacity(piece_len);
    cur = encode(&varint(tx.output.len()), cur, &mut ret, piece_len);
    for output in &tx.output {
        cur = encode(output, cur, &mut ret, piece_len);
    }
    // Stop here; lock_time happens in the next message
    if !cur.is_empty() {
        ret.push(cur);
    }
    ret
}
