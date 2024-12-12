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

//! AES
//!
//! Port of the decrytion part of the 256-bit part of Pieter Wuille's ctaes to Rust
//! Plus CTR mode. Used for ICBOC importing
//!
//!

#![allow(non_snake_case)]
#![allow(clippy::manual_rotate)]
#![allow(clippy::needless_late_init)]
#![allow(clippy::wrong_self_convention)]

const N_ROUNDS: usize = 14;
const N_KEYWORDS: usize = 8;

#[derive(Default)]
struct State {
    slice: [u16; 8],
}

impl State {
    /// colmun_0(ret) = column_col(self)
    fn from_column(&self, col: usize) -> State {
        State {
            slice: [
                (self.slice[0] >> col) & 0x1111,
                (self.slice[1] >> col) & 0x1111,
                (self.slice[2] >> col) & 0x1111,
                (self.slice[3] >> col) & 0x1111,
                (self.slice[4] >> col) & 0x1111,
                (self.slice[5] >> col) & 0x1111,
                (self.slice[6] >> col) & 0x1111,
                (self.slice[7] >> col) & 0x1111,
            ],
        }
    }

    /// Convert a byte to sliced form, storing it corresponding to given row and column
    fn load_byte(&mut self, mut byte: u8, row: usize, col: usize) {
        for i in 0..8 {
            self.slice[i] |= ((byte as u16) & 1) << (row * 4 + col);
            byte /= 2;
        }
    }

    /// Load 16 bytes of data into 8 sliced integers
    fn load_bytes(&mut self, data16: &[u8]) {
        for col in 0..4 {
            for row in 0..4 {
                self.load_byte(data16[4 * col + row], row, col);
            }
        }
    }

    /// Convert 8 sliced integers into 16 bytes of data
    fn save_bytes(&self) -> [u8; 16] {
        let mut ret = [0; 16];
        for col in 0..4 {
            for row in 0..4 {
                let mut v = 0;
                for b in 0..8 {
                    v |= ((self.slice[b] >> (4 * row + col)) & 1) << b;
                }
                ret[4 * col + row] = v as u8;
            }
        }
        ret
    }

    fn shift_rows(&mut self) {
        fn bit_range(from: usize, to: usize) -> u16 {
            ((1u16 << (to - from)) - 1) << from
        }
        fn bit_range_left(x: u16, from: usize, to: usize, shift: usize) -> u16 {
            (x & bit_range(from, to)) << shift
        }
        fn bit_range_right(x: u16, from: usize, to: usize, shift: usize) -> u16 {
            (x & bit_range(from, to)) >> shift
        }

        for i in 0..8 {
            let v = self.slice[i];
            self.slice[i] = (v & bit_range(0, 4))
                | bit_range_left(v, 4, 5, 3)
                | bit_range_right(v, 5, 8, 1)
                | bit_range_left(v, 8, 10, 2)
                | bit_range_right(v, 10, 12, 2)
                | bit_range_left(v, 12, 15, 1)
                | bit_range_right(v, 15, 16, 3);
        }
    }

    /// Multiply the cells by x, as polynomials over GF(2) mod x^8 + x^4 + x^3 + x + 1
    fn mult_x(&mut self) {
        let top = self.slice[7];
        self.slice[7] = self.slice[6];
        self.slice[6] = self.slice[5];
        self.slice[5] = self.slice[4];
        self.slice[4] = self.slice[3] ^ top;
        self.slice[3] = self.slice[2] ^ top;
        self.slice[2] = self.slice[1];
        self.slice[1] = self.slice[0] ^ top;
        self.slice[0] = top;
    }

    /// Rotate the rows one positino upwards, and xor in r
    fn key_setup_transform(&mut self, other: &Self) {
        for b in 0..8 {
            self.slice[b] = ((self.slice[b] >> 4) | (self.slice[b] << 12)) ^ other.slice[b];
        }
    }

    /// column_c1(r) |= (column_0(self) ^= column_c2(a))
    fn key_setup_column_mix(
        &mut self,
        other: &mut [Self],
        r_idx: usize,
        a_idx: usize,
        c1: usize,
        c2: usize,
    ) {
        for b in 0..8 {
            self.slice[b] ^= (other[a_idx].slice[b] >> c2) & 0x1111;
            other[r_idx].slice[b] |= (self.slice[b] & 0x1111) << c1;
        }
    }

    /// Adds a round key to the given state
    fn add_round_key(&mut self, round: &State) {
        for b in 0..8 {
            self.slice[b] ^= round.slice[b];
        }
    }

    /// S-box implementation based on the gate logic from:
    ///     Joan Boyar and Rene Peralta, A depth-16 circuit for the AES S-box.
    ///     https://eprint.iacr.org/2011/332.pdf
    fn sub_bytes(&mut self, invert: bool) {
        /* Load the bit slices */
        let U0: u16 = self.slice[7];
        let U1: u16 = self.slice[6];
        let U2: u16 = self.slice[5];
        let U3: u16 = self.slice[4];
        let U4: u16 = self.slice[3];
        let U5: u16 = self.slice[2];
        let U6: u16 = self.slice[1];
        let U7: u16 = self.slice[0];

        let T1: u16;
        let T2: u16;
        let T3: u16;
        let T4: u16;
        let T5: u16;
        let T6: u16;
        let T7: u16;
        let T8: u16;
        let T9: u16;
        let T10: u16;
        let T11: u16;
        let T12: u16;
        let T13: u16;
        let T14: u16;
        let T15: u16;
        let T16: u16;
        let T17: u16;
        let T18: u16;
        let T19: u16;
        let T20: u16;
        let T21: u16;
        let T22: u16;
        let T23: u16;
        let T24: u16;
        let T25: u16;
        let T26: u16;
        let T27: u16;
        let D: u16;
        let M1: u16;
        let M6: u16;
        let M11: u16;
        let M13: u16;
        let M15: u16;
        let M20: u16;
        let M21: u16;
        let M22: u16;
        let M23: u16;
        let M25: u16;
        let M37: u16;
        let M38: u16;
        let M39: u16;
        let M40: u16;
        let M41: u16;
        let M42: u16;
        let M43: u16;
        let M44: u16;
        let M45: u16;
        let M46: u16;
        let M47: u16;
        let M48: u16;
        let M49: u16;
        let M50: u16;
        let M51: u16;
        let M52: u16;
        let M53: u16;
        let M54: u16;
        let M55: u16;
        let M56: u16;
        let M57: u16;
        let M58: u16;
        let M59: u16;
        let M60: u16;
        let M61: u16;
        let M62: u16;
        let M63: u16;

        if invert {
            let R5: u16;
            let R13: u16;
            let R17: u16;
            let R18: u16;
            let R19: u16;
            /* Undo linear postprocessing */
            T23 = U0 ^ U3;
            T22 = !(U1 ^ U3);
            T2 = !(U0 ^ U1);
            T1 = U3 ^ U4;
            T24 = !(U4 ^ U7);
            R5 = U6 ^ U7;
            T8 = !(U1 ^ T23);
            T19 = T22 ^ R5;
            T9 = !(U7 ^ T1);
            T10 = T2 ^ T24;
            T13 = T2 ^ R5;
            T3 = T1 ^ R5;
            T25 = !(U2 ^ T1);
            R13 = U1 ^ U6;
            T17 = !(U2 ^ T19);
            T20 = T24 ^ R13;
            T4 = U4 ^ T8;
            R17 = !(U2 ^ U5);
            R18 = !(U5 ^ U6);
            R19 = !(U2 ^ U4);
            D = U0 ^ R17;
            T6 = T22 ^ R17;
            T16 = R13 ^ R19;
            T27 = T1 ^ R18;
            T15 = T10 ^ T27;
            T14 = T10 ^ R18;
            T26 = T3 ^ T16;
        } else {
            /* Linear preprocessing. */
            T1 = U0 ^ U3;
            T2 = U0 ^ U5;
            T3 = U0 ^ U6;
            T4 = U3 ^ U5;
            T5 = U4 ^ U6;
            T6 = T1 ^ T5;
            T7 = U1 ^ U2;
            T8 = U7 ^ T6;
            T9 = U7 ^ T7;
            T10 = T6 ^ T7;
            T11 = U1 ^ U5;
            T12 = U2 ^ U5;
            T13 = T3 ^ T4;
            T14 = T6 ^ T11;
            T15 = T5 ^ T11;
            T16 = T5 ^ T12;
            T17 = T9 ^ T16;
            T18 = U3 ^ U7;
            T19 = T7 ^ T18;
            T20 = T1 ^ T19;
            T21 = U6 ^ U7;
            T22 = T7 ^ T21;
            T23 = T2 ^ T22;
            T24 = T2 ^ T10;
            T25 = T20 ^ T17;
            T26 = T3 ^ T16;
            T27 = T1 ^ T12;
            D = U7;
        }

        /* Non-linear transformation (shared between the forward and backward case) */
        M1 = T13 & T6;
        M6 = T3 & T16;
        M11 = T1 & T15;
        M13 = (T4 & T27) ^ M11;
        M15 = (T2 & T10) ^ M11;
        M20 = T14 ^ M1 ^ (T23 & T8) ^ M13;
        M21 = (T19 & D) ^ M1 ^ T24 ^ M15;
        M22 = T26 ^ M6 ^ (T22 & T9) ^ M13;
        M23 = (T20 & T17) ^ M6 ^ M15 ^ T25;
        M25 = M22 & M20;
        M37 = M21 ^ ((M20 ^ M21) & (M23 ^ M25));
        M38 = M20 ^ M25 ^ (M21 | (M20 & M23));
        M39 = M23 ^ ((M22 ^ M23) & (M21 ^ M25));
        M40 = M22 ^ M25 ^ (M23 | (M21 & M22));
        M41 = M38 ^ M40;
        M42 = M37 ^ M39;
        M43 = M37 ^ M38;
        M44 = M39 ^ M40;
        M45 = M42 ^ M41;
        M46 = M44 & T6;
        M47 = M40 & T8;
        M48 = M39 & D;
        M49 = M43 & T16;
        M50 = M38 & T9;
        M51 = M37 & T17;
        M52 = M42 & T15;
        M53 = M45 & T27;
        M54 = M41 & T10;
        M55 = M44 & T13;
        M56 = M40 & T23;
        M57 = M39 & T19;
        M58 = M43 & T3;
        M59 = M38 & T22;
        M60 = M37 & T20;
        M61 = M42 & T1;
        M62 = M45 & T4;
        M63 = M41 & T2;

        if invert {
            /* Undo linear preprocessing */
            let P0 = M52 ^ M61;
            let P1 = M58 ^ M59;
            let P2 = M54 ^ M62;
            let P3 = M47 ^ M50;
            let P4 = M48 ^ M56;
            let P5 = M46 ^ M51;
            let P6 = M49 ^ M60;
            let P7 = P0 ^ P1;
            let P8 = M50 ^ M53;
            let P9 = M55 ^ M63;
            let P10 = M57 ^ P4;
            let P11 = P0 ^ P3;
            let P12 = M46 ^ M48;
            let P13 = M49 ^ M51;
            let P14 = M49 ^ M62;
            let P15 = M54 ^ M59;
            let P16 = M57 ^ M61;
            let P17 = M58 ^ P2;
            let P18 = M63 ^ P5;
            let P19 = P2 ^ P3;
            let P20 = P4 ^ P6;
            let P22 = P2 ^ P7;
            let P23 = P7 ^ P8;
            let P24 = P5 ^ P7;
            let P25 = P6 ^ P10;
            let P26 = P9 ^ P11;
            let P27 = P10 ^ P18;
            let P28 = P11 ^ P25;
            let P29 = P15 ^ P20;
            self.slice[7] = P13 ^ P22;
            self.slice[6] = P26 ^ P29;
            self.slice[5] = P17 ^ P28;
            self.slice[4] = P12 ^ P22;
            self.slice[3] = P23 ^ P27;
            self.slice[2] = P19 ^ P24;
            self.slice[1] = P14 ^ P23;
            self.slice[0] = P9 ^ P16;
        } else {
            /* Linear postprocessing */
            let L0 = M61 ^ M62;
            let L1 = M50 ^ M56;
            let L2 = M46 ^ M48;
            let L3 = M47 ^ M55;
            let L4 = M54 ^ M58;
            let L5 = M49 ^ M61;
            let L6 = M62 ^ L5;
            let L7 = M46 ^ L3;
            let L8 = M51 ^ M59;
            let L9 = M52 ^ M53;
            let L10 = M53 ^ L4;
            let L11 = M60 ^ L2;
            let L12 = M48 ^ M51;
            let L13 = M50 ^ L0;
            let L14 = M52 ^ M61;
            let L15 = M55 ^ L1;
            let L16 = M56 ^ L0;
            let L17 = M57 ^ L1;
            let L18 = M58 ^ L8;
            let L19 = M63 ^ L4;
            let L20 = L0 ^ L1;
            let L21 = L1 ^ L7;
            let L22 = L3 ^ L12;
            let L23 = L18 ^ L2;
            let L24 = L15 ^ L9;
            let L25 = L6 ^ L10;
            let L26 = L7 ^ L9;
            let L27 = L8 ^ L10;
            let L28 = L11 ^ L14;
            let L29 = L11 ^ L17;
            self.slice[7] = L6 ^ L24;
            self.slice[6] = !(L16 ^ L26);
            self.slice[5] = !(L19 ^ L28);
            self.slice[4] = L6 ^ L21;
            self.slice[3] = L20 ^ L22;
            self.slice[2] = L25 ^ L29;
            self.slice[1] = !(L13 ^ L27);
            self.slice[0] = !(L6 ^ L23);
        }
    }

    /// The MixColumns transform treats the bytes of the columns of the state as
    /// coefficients of a 3rd degree polynomial over GF(2^8) and multiplies them
    /// by the fixed polynomial a(x) = {03}x^3 + {01}x^2 + {01}x + {02}, modulo
    /// x^4 + {01}.
    ///
    /// In the inverse transform, we multiply by the inverse of a(x),
    /// a^-1(x) = {0b}x^3 + {0d}x^2 + {09}x + {0e}. This is equal to
    /// a(x) * ({04}x^2 + {05}), so we can reuse the forward transform's code
    /// (found in OpenSSL's bsaes-x86_64.pl, attributed to Jussi Kivilinna)
    ///
    /// In the bitsliced representation, a multiplication of every column by x
    /// mod x^4 + 1 is simply a right rotation.
    fn mix_columns(&mut self, invert: bool) {
        fn rot(x: u16, b: usize) -> u16 {
            (x >> (4 * b)) | (x << (4 * (4 - b)))
        }
        /* Shared for both directions is a multiplication by a(x), which can be
         * rewritten as (x^3 + x^2 + x) + {02}*(x^3 + {01}).
         *
         * First compute s into the s? variables, (x^3 + {01}) * s into the s?_01
         * variables and (x^3 + x^2 + x)*s into the s?_123 variables.
         */
        let s0 = self.slice[0];
        let s1 = self.slice[1];
        let s2 = self.slice[2];
        let s3 = self.slice[3];
        let s4 = self.slice[4];
        let s5 = self.slice[5];
        let s6 = self.slice[6];
        let s7 = self.slice[7];
        let s0_01 = s0 ^ rot(s0, 1);
        let s0_123 = rot(s0_01, 1) ^ rot(s0, 3);
        let s1_01 = s1 ^ rot(s1, 1);
        let s1_123 = rot(s1_01, 1) ^ rot(s1, 3);
        let s2_01 = s2 ^ rot(s2, 1);
        let s2_123 = rot(s2_01, 1) ^ rot(s2, 3);
        let s3_01 = s3 ^ rot(s3, 1);
        let s3_123 = rot(s3_01, 1) ^ rot(s3, 3);
        let s4_01 = s4 ^ rot(s4, 1);
        let s4_123 = rot(s4_01, 1) ^ rot(s4, 3);
        let s5_01 = s5 ^ rot(s5, 1);
        let s5_123 = rot(s5_01, 1) ^ rot(s5, 3);
        let s6_01 = s6 ^ rot(s6, 1);
        let s6_123 = rot(s6_01, 1) ^ rot(s6, 3);
        let s7_01 = s7 ^ rot(s7, 1);
        let s7_123 = rot(s7_01, 1) ^ rot(s7, 3);
        /* Now compute s = s?_123 + {02} * s?_01. */
        self.slice[0] = s7_01 ^ s0_123;
        self.slice[1] = s7_01 ^ s0_01 ^ s1_123;
        self.slice[2] = s1_01 ^ s2_123;
        self.slice[3] = s7_01 ^ s2_01 ^ s3_123;
        self.slice[4] = s7_01 ^ s3_01 ^ s4_123;
        self.slice[5] = s4_01 ^ s5_123;
        self.slice[6] = s5_01 ^ s6_123;
        self.slice[7] = s6_01 ^ s7_123;
        if invert {
            /* In the reverse direction, we further need to multiply by
             * {04}x^2 + {05}, which can be written as {04} * (x^2 + {01}) + {01}.
             *
             * First compute (x^2 + {01}) * s into the t?_02 variables: */
            let t0_02 = self.slice[0] ^ rot(self.slice[0], 2);
            let t1_02 = self.slice[1] ^ rot(self.slice[1], 2);
            let t2_02 = self.slice[2] ^ rot(self.slice[2], 2);
            let t3_02 = self.slice[3] ^ rot(self.slice[3], 2);
            let t4_02 = self.slice[4] ^ rot(self.slice[4], 2);
            let t5_02 = self.slice[5] ^ rot(self.slice[5], 2);
            let t6_02 = self.slice[6] ^ rot(self.slice[6], 2);
            let t7_02 = self.slice[7] ^ rot(self.slice[7], 2);
            /* And then update s += {04} * t?_02 */
            self.slice[0] ^= t6_02;
            self.slice[1] ^= t6_02 ^ t7_02;
            self.slice[2] ^= t0_02 ^ t7_02;
            self.slice[3] ^= t1_02 ^ t6_02;
            self.slice[4] ^= t2_02 ^ t6_02 ^ t7_02;
            self.slice[5] ^= t3_02 ^ t7_02;
            self.slice[6] ^= t4_02;
            self.slice[7] ^= t5_02;
        }
    }
}

/// Opaque AES decryption context
struct Aes256Context {
    rk: [State; 15],
}

impl Aes256Context {
    /// Create a new initialized AES256 context
    pub fn new(key: [u8; 32]) -> Aes256Context {
        let mut ret = Aes256Context {
            rk: Default::default(),
        };
        // The first nkeywords round columns are just taken from the key directly
        for col in 0..N_KEYWORDS {
            for row in 0..4 {
                ret.rk[col / 4].load_byte(key[4 * col + row], row, col % 4);
            }
        }

        let mut column = ret.rk[(N_KEYWORDS - 1) / 4].from_column((N_KEYWORDS - 1) % 4);
        let mut rcon = State {
            slice: [1, 0, 0, 0, 0, 0, 0, 0],
        };

        let mut pos = 0;
        for i in N_KEYWORDS..4 * (N_ROUNDS + 1) {
            if pos == 0 {
                column.sub_bytes(false);
                column.key_setup_transform(&rcon);
                rcon.mult_x();
            } else if pos == 4 {
                column.sub_bytes(false);
            }
            pos = (pos + 1) % N_KEYWORDS;
            column.key_setup_column_mix(
                &mut ret.rk[..],
                i / 4,
                (i - N_KEYWORDS) / 4,
                i % 4,
                (i - N_KEYWORDS) % 4,
            );
        }

        ret
    }

    fn encrypt(&self, plain16: &[u8]) -> [u8; 16] {
        /* Most AES decryption implementations use the alternate scheme
         * (the Equivalent Inverse Cipher), which allows for more code reuse between
         * the encryption and decryption code, but requires separate setup for both.
         */
        let mut s = State::default();

        s.load_bytes(plain16);
        s.add_round_key(&self.rk[0]);
        for round in &self.rk[1..N_ROUNDS] {
            s.sub_bytes(false);
            s.shift_rows();
            s.mix_columns(false);
            s.add_round_key(round);
        }
        s.sub_bytes(false);
        s.shift_rows();
        s.add_round_key(&self.rk[N_ROUNDS]);

        s.save_bytes()
    }
}

fn inc_iv(iv16: &mut [u8]) {
    let mut idx = 15;
    while iv16[idx] == 0xff {
        iv16[idx] = 0;
        idx -= 1;
    }
    iv16[idx] += 1;
}

pub fn aes256_decrypt_ctr(key: [u8; 32], iv16: &mut [u8], mut cipher: &[u8]) -> Vec<u8> {
    assert_eq!(cipher.len() % 16, 0);
    let mut ret = Vec::with_capacity(cipher.len());
    let ctx = Aes256Context::new(key);
    while !cipher.is_empty() {
        let xor = ctx.encrypt(&*iv16);
        for ch in &xor {
            ret.push(*ch ^ cipher[0]);
            cipher = &cipher[1..];
        }
        inc_iv(&mut *iv16);
    }
    ret
}
