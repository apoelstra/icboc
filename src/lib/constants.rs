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

//! # Constants
//!
//! Various constants
//!

/// HID-related constants
pub mod hid {
    /// Constants for the Nano S specifically
    pub mod nano_s {
        /// USB vendor ID for the Nano S
        pub const VENDOR_ID: u16 = 0x2c97;
        /// USB product ID for the Nano S
        pub const PRODUCT_ID: u16 = 0x0001;
    }
}

/// Communication constants
pub mod apdu {
    /// Ledger-specific APDU constants
    #[allow(missing_docs)]
    pub mod ledger {
        pub const DEFAULT_CHANNEL: u16 = 0x0101;
        pub const TAG_APDU: u8 = 0x05;
        /// Maximum size an individual HID message can be
        pub const PACKET_SIZE: usize = 64;
        /// Maximum size a full APDU (split across HID frames) can be
        pub const MAX_APDU_SIZE: usize = 255 + 5; // from nanos-secure-sdk/include/os.h IO_APDU_BUFFER_SIZE

        pub const BTCHIP_CLA: u8 = 0xe0;

        /// Instructions
        #[derive(Copy, Clone, PartialEq, Eq, Debug)]
        pub enum Instruction {
            SetAlternateCoinVersion,
            GetWalletPublicKey,
            GetTrustedInput,
            UntrustedHashTransactionInputStart,
            UntrustedHashSign,
            UntrustedHashTransactionInputFinalize,
            SignMessage,
            GetRandom,
            GetFirmwareVersion,
        }

        impl Instruction {
            pub fn into_u8(self) -> u8 {
                match self {
                    Instruction::SetAlternateCoinVersion => 0x14,
                    Instruction::GetWalletPublicKey => 0x40,
                    Instruction::GetTrustedInput => 0x42,
                    Instruction::UntrustedHashTransactionInputStart => 0x44,
                    Instruction::UntrustedHashSign => 0x48,
                    Instruction::UntrustedHashTransactionInputFinalize => 0x4a,
                    Instruction::SignMessage => 0x4e,
                    Instruction::GetRandom => 0xc0,
                    Instruction::GetFirmwareVersion => 0xc4,
                }
            }

            pub fn from_u8(b: u8) -> Option<Self> {
                match b {
                    0x14 => Some(Instruction::SetAlternateCoinVersion),
                    0x40 => Some(Instruction::GetWalletPublicKey),
                    0x42 => Some(Instruction::GetTrustedInput),
                    0x44 => Some(Instruction::UntrustedHashTransactionInputStart),
                    0x48 => Some(Instruction::UntrustedHashSign),
                    0x4a => Some(Instruction::UntrustedHashTransactionInputFinalize),
                    0x4e => Some(Instruction::SignMessage),
                    0xc0 => Some(Instruction::GetRandom),
                    0xc4 => Some(Instruction::GetFirmwareVersion),
                    _ => None,
                }
            }
        }

        /// Status Words
        pub mod sw {
            pub const OK: u16 = 0x9000;
            pub const BAD_LENGTH: u16 = 0x6700;
            pub const BAD_DATA: u16 = 0x6A80;
            pub const BAD_P1_OR_P2: u16 = 0x6B00;
            pub const INS_NOT_SUPPORTED: u16 = 0x6D00;
            pub const DONGLE_LOCKED: u16 = 0x6982;
            pub const SIGN_REFUSED: u16 = 0x6985;
            pub mod exception {
                pub const EXCEPTION: u16 = 0x6F01;
                pub const INVALID_PARAMETER: u16 = 0x6F02;
                pub const HALTED: u16 = 0x6FAA;
            }
        }
    }
}

/// Wallet structure constants
pub mod wallet {
    /// Magic bytes indicating a wallet file (bottom two are a version)
    /// First six bytes are guaranteed random: used `wget boards.4chan.org/b/ -O - | sha256sum` to compute
    pub const MAGIC: u64 = 0x3160_f90d_aae5_0003;
    /// Magic bytes indicating a testnet wallet file
    pub const MAGIC_TESTNET: u64 = 0x3160_f90d_aae5_0004;
    /// Size, in bytes, of the data block for each entry.
    pub const DECRYPTED_ENTRY_SIZE: usize = 336;
    /// Size, in bytes, of the AES-CTR-encrypted data block.
    pub const ENCRYPTED_ENTRY_SIZE: usize = 352;
    /// Maximum length in bytes of the user ID field
    pub const MAX_USER_ID_BYTES: usize = 32;
    /// Maximum length in bytes of the freeform note field
    pub const MAX_NOTE_BYTES: usize = 80;
    /// An amount of satoshis which, if we have change worth less than, we simply
    /// drop it into fees
    pub const CHANGE_DUST: u64 = 1_0000; // 0.0001 BTC, around 10c USD
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apdu_instruction_round_trip() {
        for byte in 0..256 {
            let byte = byte as u8;
            if let Some(ins) = apdu::ledger::Instruction::from_u8(byte) {
                assert_eq!(byte, ins.into_u8());
            }
        }
    }
}


