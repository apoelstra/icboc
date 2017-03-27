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
        pub const PACKET_SIZE: usize = 64;

        pub const BTCHIP_CLA: u8 = 0xe0;

        /// Instructions
        pub mod ins {
            pub const GET_FIRMWARE_VERSION: u8 = 0xc4;
        }

        /// Status Words
        pub mod sw {
            pub const OK: u16 = 0x9000;
            pub const INS_NOT_SUPPORTED: u16 = 0x6D00;
        }
    }
}


