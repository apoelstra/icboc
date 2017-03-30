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
        pub mod ins {
            pub const GET_WALLET_PUBLIC_KEY: u8 = 0x40;
            pub const GET_TRUSTED_INPUT: u8 = 0x42;
            pub const UNTRUSTED_HASH_TRANSACTION_INPUT_START: u8 = 0x44;
            pub const UNTRUSTED_HASH_SIGN: u8 = 0x48;
            pub const UNTRUSTED_HASH_TRANSACTION_INPUT_FINALIZE: u8 = 0x4a;
            pub const SIGN_MESSAGE: u8 = 0x4e;
            pub const GET_RANDOM: u8 = 0xc0;
            pub const GET_FIRMWARE_VERSION: u8 = 0xc4;
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
    pub const MAGIC: u64 = 0x3160_f90d_aae5_0001;
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


