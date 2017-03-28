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

//! # Ledger Dongle
//!
//! Specific support for Ledger-branded dongles
//!

use byteorder::{ByteOrder, BigEndian};
use hex::ToHex;
use hid;
use log::LogLevel;
use std::cmp;
use std::time::Duration;

use constants;
use dongle::message::Command;
use error::Error;

use super::{Dongle, Product};

/// Structure representing the device
pub struct HardDongle {
    /// The HID manager is an object that must be kept alive as long as the HID
    /// handle is, so we keep it in the struct beside the handle
    _hid_manager: hid::Manager,
    /// Similarly, the handle itself must be in an Option so that we can force
    /// it to drop before the manager is deallocated
    handle: Option<hid::Handle>,
    product: Product,
}

impl Drop for HardDongle {
    // Manually drop to ensure handle is dropped before the manager
    fn drop(&mut self) {
        self.handle.take();
    }
}

impl Dongle for HardDongle {
    fn product(&self) -> Product {
        self.product
    }

    fn exchange<C: Command>(&mut self, mut cmd: C) -> Result<(u16, Vec<u8>), Error> {
        let handle = self.handle.as_mut().unwrap();
        while let Some(msg) = cmd.encode_next() {
            write_apdu(handle, &msg)?;
            let reply = read_apdu(handle, Duration::from_secs(120))?;  // TODO make 2min configurable
            cmd.decode_reply(reply)?
        }
        Ok(cmd.into_reply())
    }
}

/// Function to get a handle of the device. Errors out if the device
/// cannot be accessed or if there are more than one potential devices.
pub fn get_unique() -> Result<HardDongle, Error> {
    let hid = try!(hid::init());

    let mut found_count = 0;
    let mut found_dev = None;
    for hid_dev in hid.devices() {
        match (hid_dev.product_id(), hid_dev.vendor_id()) {
            (constants::hid::nano_s::PRODUCT_ID,
             constants::hid::nano_s::VENDOR_ID) => {
                 found_count += 1;
                 // Note that this `hid_dev.open()` will be closed when the object is
                 // dropped, i.e. if it is overwritten or if the user destroyes the
                 // returned `HardDongle` object
                 found_dev = Some(try!(hid_dev.open()));
            }
            _ => {}
        }
    }

    match found_count {
        0 => Err(Error::DongleNotFound),
        1 => Ok(HardDongle {
            _hid_manager: hid,
            handle: found_dev, // guaranteed to be Some(handle)
            product: Product::NanoS
        }),
        _ => Err(Error::DongleNotUnique)
    }
}

/// Write a message encoded as a APDU to the Ledger device
fn write_apdu(handle: &mut hid::Handle, mut data: &[u8]) -> Result<(), Error> {
    assert!(data.len() > 0);
    assert!(data.len() < 0x1000);

    let mut w = handle.data();

    if log_enabled!(LogLevel::Debug) {
        trace!("Sending message {}", data.to_hex());
    }

    let mut sequence_no = 0u16;
    while !data.is_empty() {
        let mut data_frame = [0u8; constants::apdu::ledger::PACKET_SIZE];
        // Write header
        BigEndian::write_u16(&mut data_frame[0..2], constants::apdu::ledger::DEFAULT_CHANNEL);
        data_frame[2] = constants::apdu::ledger::TAG_APDU;
        BigEndian::write_u16(&mut data_frame[3..5], sequence_no);
        // First packet's header includes a two-byte length
        let header_len;
        if sequence_no == 0 {
            BigEndian::write_u16(&mut data_frame[5..7], data.len() as u16);
            header_len = 7;
        } else {
            header_len = 5;
        }
        let packet_len = data_frame.len() - header_len;

        if data.len() > packet_len {
            data_frame[header_len..].clone_from_slice(&data[0..packet_len]);
            data = &data[packet_len..];
        } else {
            data_frame[header_len..header_len + data.len()].clone_from_slice(data);
            data = &data[data.len()..];
        }
        try!(w.write(&data_frame[..]));

        if log_enabled!(LogLevel::Debug) {
            use hex::ToHex;
            trace!("Sending dataframe {}", (&data_frame[..]).to_hex());
        }

        sequence_no += 1;
    }
    Ok(())
}

/// Read a message encoded as a APDU from the Ledger device
fn read_apdu(handle: &mut hid::Handle, timeout: Duration) -> Result<Vec<u8>, Error> {
    let mut r = handle.data();

    let mut sequence_no = 0u16;
    let mut receive_len = 1;  // dummy value >0, will be reset on first iteration
    let mut ret = vec![];
    while receive_len > 0 {
        // Read next frame
        let mut data_frame = [0u8; constants::apdu::ledger::PACKET_SIZE];
        let read_n = try!(r.read(&mut data_frame[..], timeout));
        if read_n.is_none() {
            return Err(Error::UnexpectedEof);
        }

        // Sanity check the frame
        let r_channel = BigEndian::read_u16(&data_frame[0..2]);
        if r_channel != constants::apdu::ledger::DEFAULT_CHANNEL {
            return Err(Error::ApduWrongChannel);
        }
        let r_tag = data_frame[2];
        if r_tag != constants::apdu::ledger::TAG_APDU {
            return Err(Error::ApduWrongTag);
        }
        let r_sequence_no = BigEndian::read_u16(&data_frame[3..5]);
        if r_sequence_no != sequence_no {
            return Err(Error::ApduWrongSequence);
        }

        // Extract the message
        let header_len;
        if sequence_no == 0 {
            receive_len = BigEndian::read_u16(&data_frame[5..7]) as usize;
            ret = Vec::with_capacity(receive_len as usize);
            header_len = 7;
        } else {
            header_len = 5;
        }
        let message_len = cmp::min(receive_len, data_frame.len() - header_len);
        ret.extend(&data_frame[header_len..header_len + message_len]);

        if log_enabled!(LogLevel::Debug) {
            trace!("Got dataframe {}", (&data_frame[..]).to_hex());
        }

        sequence_no += 1;
        receive_len -= message_len;
    }
    if log_enabled!(LogLevel::Debug) {
        trace!("Got message {}", ret.to_hex());
    }
    Ok(ret)
}


