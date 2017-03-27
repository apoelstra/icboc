// IceBox
// Written in 2017 by
//   Andrew Poelstra <icebox@wpsoftware.net>
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

use crypto::digest::Digest;
use crypto::sha2;
use secp256k1::{Secp256k1, ContextFlag, Signature};
use secp256k1::key::SecretKey;

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
    use hex::ToHex;
    println!("Convert {}", (&sig[..]).to_hex());
    println!("     To {}", (&ret[..]).to_hex());
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
    use hex::ToHex;
    println!("Convert {}", (&sig[..]).to_hex());
    println!("     To {}", (&rv[..]).to_hex());
    let mut sig = Signature::from_der_lax(&secp, &rv)?;
    sig.normalize_s(&secp);
    Ok(sig)
}

