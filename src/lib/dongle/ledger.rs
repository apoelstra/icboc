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

//! # Ledger Dongle
//!
//! Specific support for Ledger-branded dongles
//!

use core::cmp;
use core::convert::TryFrom as _;
use std::time::Duration;

use crate::constants::apdu::ledger;
use crate::dongle::{message::Command, Dongle};
use crate::{constants, hid, Error};

/// Structure representing the device
pub struct NanoS {
    hid_dev: hid::Device,
}

impl Dongle for NanoS {
    fn exchange<C: Command>(&mut self, mut cmd: C) -> Result<(u16, Vec<u8>), Error> {
        while let Some(msg) = cmd.encode_next(constants::apdu::ledger::MAX_APDU_SIZE) {
            write_apdu(&self.hid_dev, &msg)?;
            let reply = read_apdu(&self.hid_dev, Duration::from_secs(30))?; // TODO make this configurable
            cmd.decode_reply(reply)?;
        }
        Ok(cmd.into_reply())
    }
}

impl NanoS {
    /// Function to get a handle of the device. Errors out if the device
    /// cannot be accessed or if there are more than one potential devices.
    pub fn get(hid: &hid::Api) -> Result<NanoS, Error> {
        let mut found_dev = None;
        for hid_dev in hid.device_list() {
            if hid_dev.product_id() == constants::hid::nano_s::PRODUCT_ID
                && hid_dev.vendor_id() == constants::hid::nano_s::VENDOR_ID
                && (hid_dev.interface_number() == 0 || hid_dev.usage_page() == 0xffa0)
            {
                if found_dev.is_some() {
                    return Err(Error::DongleNotUnique);
                }
                found_dev = Some(hid_dev);
            }
        }

        match found_dev {
            Some(hid_dev) => Ok(NanoS {
                hid_dev: hid_dev.open_device(hid)?,
            }),
            None => Err(Error::DongleNotFound),
        }
    }
}

/// Write a message encoded as a APDU to the Ledger device
fn write_apdu(hid_dev: &hid::Device, mut data: &[u8]) -> Result<(), hid::Error> {
    assert!(!data.is_empty());
    assert!(data.len() < 0x1000);

    let mut sequence_no = 0u16;
    while !data.is_empty() {
        let mut data_frame = [0u8; constants::apdu::ledger::PACKET_SIZE];
        // Write header
        data_frame[0..2].copy_from_slice(&constants::apdu::ledger::DEFAULT_CHANNEL.to_be_bytes());
        data_frame[2] = constants::apdu::ledger::TAG_APDU;
        data_frame[3..5].copy_from_slice(&sequence_no.to_be_bytes());

        // First packet's header includes a two-byte length
        let header_len = if sequence_no == 0 {
            data_frame[5..7].copy_from_slice(
                &u16::try_from(data.len())
                    .expect("length < 2^16")
                    .to_be_bytes(),
            );
            7
        } else {
            5
        };
        let packet_len = data_frame.len() - header_len;

        if data.len() > packet_len {
            data_frame[header_len..].clone_from_slice(&data[0..packet_len]);
            data = &data[packet_len..];
        } else {
            data_frame[header_len..header_len + data.len()].clone_from_slice(data);
            data = &data[data.len()..];
        }
        hid_dev.write(&data_frame[..])?;

        sequence_no += 1;
    }
    Ok(())
}

/// Read a message encoded as a APDU from the Ledger device
fn read_apdu(hid_dev: &hid::Device, timeout: Duration) -> Result<Vec<u8>, Error> {
    let mut sequence_no = 0u16;
    let mut receive_len = 1; // dummy value >0, will be reset on first iteration
    let mut ret = vec![];
    while receive_len > 0 {
        // Read next frame
        let mut data_frame = [0u8; constants::apdu::ledger::PACKET_SIZE];
        let mut frame_ptr = &mut data_frame[..];
        while !frame_ptr.is_empty() {
            let n_read_bytes = hid_dev.read_timeout(frame_ptr, timeout.as_millis() as i32)?;
            frame_ptr = &mut frame_ptr[n_read_bytes..];
        }

        // Sanity check the frame
        let r_channel = u16::from_be_bytes([data_frame[0], data_frame[1]]);
        if r_channel != ledger::DEFAULT_CHANNEL {
            return Err(Error::ApduWrongChannel {
                expected: ledger::DEFAULT_CHANNEL,
                found: r_channel,
            });
        }
        let r_tag = data_frame[2];
        if r_tag != ledger::TAG_APDU {
            return Err(Error::ApduWrongTag {
                expected: ledger::TAG_APDU,
                found: r_tag,
            });
        }
        let r_sequence_no = u16::from_be_bytes([data_frame[3], data_frame[4]]);
        if r_sequence_no != sequence_no {
            return Err(Error::ApduWrongSequence {
                expected: sequence_no,
                found: r_sequence_no,
            });
        }

        // Extract the message
        let header_len;
        if sequence_no == 0 {
            receive_len = usize::from(u16::from_be_bytes([data_frame[5], data_frame[6]]));
            ret = Vec::with_capacity(receive_len);
            header_len = 7;
        } else {
            header_len = 5;
        }
        let message_len = cmp::min(receive_len, data_frame.len() - header_len);
        ret.extend(&data_frame[header_len..header_len + message_len]);

        sequence_no += 1;
        receive_len -= message_len;
    }
    Ok(ret)
}
