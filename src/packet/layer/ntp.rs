//! Network Time Protocol (NTP).
//!
//! NTP starts with a fixed 48-byte header containing leap/version/mode fields,
//! timing parameters, and four 64-bit timestamps. Extension fields or message
//! authentication data may follow the fixed header and are exposed as payload
//! bytes.
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |LI | VN  |Mode |    Stratum    |     Poll      |  Precision    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         Root Delay                            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                      Root Dispersion                          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                      Reference ID                             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! +                    Reference Timestamp                       +
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! +                    Originate Timestamp                       +
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! +                     Receive Timestamp                        +
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! +                     Transmit Timestamp                       +
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                 Extensions or authenticator                   |
//! ~                              ...                              ~
//! ```

use std::fmt::Debug;

use crate::{
    field_spec,
    packet::{
        ParseContext,
        layer::{Protocol, ProtocolExt},
        utils::field::{FieldMut, FieldRef},
    },
};

pub mod leap_indicator;
pub mod mode;

pub use leap_indicator::NtpLeapIndicator;
pub use mode::NtpMode;

/// Network Time Protocol (NTP) LayerKind.
#[derive(Debug, Clone, Copy)]
pub struct Ntp;

impl Ntp {
    /// NTP fixed header length.
    const MIN_LEN: usize = 48;
}

impl Protocol for Ntp {
    fn display(&self, bytes: &[u8], fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ntp = NtpViewer::new(bytes);

        write!(
            fmt,
            "[Ntp] v{} {} stratum {}",
            ntp.version().get(),
            ntp.mode().get(),
            ntp.stratum().get()
        )
    }
}

impl ProtocolExt for Ntp {
    type Viewer<'a> = NtpViewer<&'a [u8]>;
    type ViewerMut<'a> = NtpViewer<&'a mut [u8]>;

    fn parse(
        ctx: &mut ParseContext,
        offset: usize,
    ) -> Result<(), crate::packet::error::ParseError> {
        ctx.require(&Ntp, offset, Ntp::MIN_LEN)?;

        ctx.push_layer(&Ntp, offset, ctx.bytes.len() - offset);

        Ok(())
    }

    fn view<'a>(bytes: &'a [u8]) -> Self::Viewer<'a> {
        NtpViewer::new(bytes)
    }

    fn view_mut<'a>(bytes: &'a mut [u8]) -> Self::ViewerMut<'a> {
        NtpViewer::new(bytes)
    }
}

field_spec!(LeapIndicatorSpec, NtpLeapIndicator, u8, 0xC0, 6);
field_spec!(VersionSpec, u8, u8, 0x38, 3);
field_spec!(ModeSpec, NtpMode, u8, 0x07);
field_spec!(StratumSpec, u8, u8);
field_spec!(PollSpec, i8, u8);
field_spec!(PrecisionSpec, i8, u8);
field_spec!(RootDelaySpec, u32, u32);
field_spec!(RootDispersionSpec, u32, u32);
field_spec!(TimestampSpec, u64, u64);

/// Network Time Protocol (NTP).
pub struct NtpViewer<T>
where
    T: AsRef<[u8]>,
{
    data: T,
}

impl<T> NtpViewer<T>
where
    T: AsRef<[u8]>,
{
    /// Field range of the leap indicator/version/mode octet: 0..1
    const FIELD_FLAGS: core::ops::Range<usize> = 0..1;
    /// Field range of the stratum: 1..2
    const FIELD_STRATUM: core::ops::Range<usize> = 1..2;
    /// Field range of the poll interval exponent: 2..3
    const FIELD_POLL: core::ops::Range<usize> = 2..3;
    /// Field range of the precision exponent: 3..4
    const FIELD_PRECISION: core::ops::Range<usize> = 3..4;
    /// Field range of the root delay: 4..8
    const FIELD_ROOT_DELAY: core::ops::Range<usize> = 4..8;
    /// Field range of the root dispersion: 8..12
    const FIELD_ROOT_DISPERSION: core::ops::Range<usize> = 8..12;
    /// Field range of the reference identifier: 12..16
    const FIELD_REFERENCE_ID: core::ops::Range<usize> = 12..16;
    /// Field range of the reference timestamp: 16..24
    const FIELD_REFERENCE_TIMESTAMP: core::ops::Range<usize> = 16..24;
    /// Field range of the originate timestamp: 24..32
    const FIELD_ORIGINATE_TIMESTAMP: core::ops::Range<usize> = 24..32;
    /// Field range of the receive timestamp: 32..40
    const FIELD_RECEIVE_TIMESTAMP: core::ops::Range<usize> = 32..40;
    /// Field range of the transmit timestamp: 40..48
    const FIELD_TRANSMIT_TIMESTAMP: core::ops::Range<usize> = 40..48;

    /// Create a new NTP viewer with the given raw data.
    pub fn new(data: T) -> Self {
        Self { data }
    }

    /// Get the inner raw data.
    pub const fn inner(&self) -> &T {
        &self.data
    }

    /// Get bytes after the fixed NTP header.
    #[inline]
    pub fn extension_bytes(&self) -> &[u8] {
        if self.data.as_ref().len() <= Ntp::MIN_LEN {
            &self.data.as_ref()[0..0]
        } else {
            &self.data.as_ref()[Ntp::MIN_LEN..]
        }
    }

    /// Get the accessor of the leap indicator.
    #[inline]
    pub fn leap_indicator(&self) -> FieldRef<'_, LeapIndicatorSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_FLAGS])
    }

    /// Get the accessor of the NTP version.
    #[inline]
    pub fn version(&self) -> FieldRef<'_, VersionSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_FLAGS])
    }

    /// Get the accessor of the mode.
    #[inline]
    pub fn mode(&self) -> FieldRef<'_, ModeSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_FLAGS])
    }

    /// Get the accessor of the stratum.
    #[inline]
    pub fn stratum(&self) -> FieldRef<'_, StratumSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_STRATUM])
    }

    /// Get the accessor of the signed poll interval exponent.
    #[inline]
    pub fn poll(&self) -> FieldRef<'_, PollSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_POLL])
    }

    /// Get the accessor of the signed precision exponent.
    #[inline]
    pub fn precision(&self) -> FieldRef<'_, PrecisionSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_PRECISION])
    }

    /// Get the accessor of the raw root delay fixed-point value.
    #[inline]
    pub fn root_delay(&self) -> FieldRef<'_, RootDelaySpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_ROOT_DELAY])
    }

    /// Get the accessor of the raw root dispersion fixed-point value.
    #[inline]
    pub fn root_dispersion(&self) -> FieldRef<'_, RootDispersionSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_ROOT_DISPERSION])
    }

    /// Get the reference identifier bytes.
    #[inline]
    pub fn reference_id(&self) -> &[u8] {
        &self.data.as_ref()[Self::FIELD_REFERENCE_ID]
    }

    /// Get the accessor of the raw reference timestamp.
    #[inline]
    pub fn reference_timestamp(&self) -> FieldRef<'_, TimestampSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_REFERENCE_TIMESTAMP])
    }

    /// Get the accessor of the raw originate timestamp.
    #[inline]
    pub fn originate_timestamp(&self) -> FieldRef<'_, TimestampSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_ORIGINATE_TIMESTAMP])
    }

    /// Get the accessor of the raw receive timestamp.
    #[inline]
    pub fn receive_timestamp(&self) -> FieldRef<'_, TimestampSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_RECEIVE_TIMESTAMP])
    }

    /// Get the accessor of the raw transmit timestamp.
    #[inline]
    pub fn transmit_timestamp(&self) -> FieldRef<'_, TimestampSpec> {
        FieldRef::new(&self.data.as_ref()[Self::FIELD_TRANSMIT_TIMESTAMP])
    }
}

impl<T> NtpViewer<T>
where
    T: AsRef<[u8]> + AsMut<[u8]>,
{
    /// Get the mutable inner raw data.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }

    /// Get mutable bytes after the fixed NTP header.
    #[inline]
    pub fn extension_bytes_mut(&mut self) -> &mut [u8] {
        let data = self.data.as_mut();
        if data.len() <= Ntp::MIN_LEN {
            &mut data[0..0]
        } else {
            &mut data[Ntp::MIN_LEN..]
        }
    }

    /// Get the mutable accessor of the leap indicator.
    #[inline]
    pub fn leap_indicator_mut(&mut self) -> FieldMut<'_, LeapIndicatorSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_FLAGS])
    }

    /// Get the mutable accessor of the NTP version.
    #[inline]
    pub fn version_mut(&mut self) -> FieldMut<'_, VersionSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_FLAGS])
    }

    /// Get the mutable accessor of the mode.
    #[inline]
    pub fn mode_mut(&mut self) -> FieldMut<'_, ModeSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_FLAGS])
    }

    /// Get the mutable accessor of the stratum.
    #[inline]
    pub fn stratum_mut(&mut self) -> FieldMut<'_, StratumSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_STRATUM])
    }

    /// Get the mutable accessor of the signed poll interval exponent.
    #[inline]
    pub fn poll_mut(&mut self) -> FieldMut<'_, PollSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_POLL])
    }

    /// Get the mutable accessor of the signed precision exponent.
    #[inline]
    pub fn precision_mut(&mut self) -> FieldMut<'_, PrecisionSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_PRECISION])
    }

    /// Get the mutable accessor of the raw root delay fixed-point value.
    #[inline]
    pub fn root_delay_mut(&mut self) -> FieldMut<'_, RootDelaySpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_ROOT_DELAY])
    }

    /// Get the mutable accessor of the raw root dispersion fixed-point value.
    #[inline]
    pub fn root_dispersion_mut(&mut self) -> FieldMut<'_, RootDispersionSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_ROOT_DISPERSION])
    }

    /// Get the mutable reference identifier bytes.
    #[inline]
    pub fn reference_id_mut(&mut self) -> &mut [u8] {
        &mut self.data.as_mut()[Self::FIELD_REFERENCE_ID]
    }

    /// Get the mutable accessor of the raw reference timestamp.
    #[inline]
    pub fn reference_timestamp_mut(&mut self) -> FieldMut<'_, TimestampSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_REFERENCE_TIMESTAMP])
    }

    /// Get the mutable accessor of the raw originate timestamp.
    #[inline]
    pub fn originate_timestamp_mut(&mut self) -> FieldMut<'_, TimestampSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_ORIGINATE_TIMESTAMP])
    }

    /// Get the mutable accessor of the raw receive timestamp.
    #[inline]
    pub fn receive_timestamp_mut(&mut self) -> FieldMut<'_, TimestampSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_RECEIVE_TIMESTAMP])
    }

    /// Get the mutable accessor of the raw transmit timestamp.
    #[inline]
    pub fn transmit_timestamp_mut(&mut self) -> FieldMut<'_, TimestampSpec> {
        FieldMut::new(&mut self.data.as_mut()[Self::FIELD_TRANSMIT_TIMESTAMP])
    }
}

impl<T> Debug for NtpViewer<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ntp")
            .field("leap_indicator", &self.leap_indicator().get())
            .field("version", &self.version().get())
            .field("mode", &self.mode().get())
            .field("stratum", &self.stratum().get())
            .field("poll", &self.poll().get())
            .field("precision", &self.precision().get())
            .field("root_delay", &self.root_delay().get())
            .field("root_dispersion", &self.root_dispersion().get())
            .field("reference_id", &self.reference_id())
            .field("reference_timestamp", &self.reference_timestamp().get())
            .field("originate_timestamp", &self.originate_timestamp().get())
            .field("receive_timestamp", &self.receive_timestamp().get())
            .field("transmit_timestamp", &self.transmit_timestamp().get())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use crate::packet::{Packet, layer::eth::Eth};

    use super::*;

    #[test]
    fn ntp_viewer() {
        let data: [u8; 48] = [
            0x24, // li: none, version: 4, mode: server
            0x02, // stratum
            0x06, // poll
            0xec, // precision: -20
            0x00, 0x01, 0x00, 0x00, // root delay
            0x00, 0x02, 0x00, 0x00, // root dispersion
            b'L', b'O', b'C', b'L', // reference id
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // reference timestamp
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // originate timestamp
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, // receive timestamp
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, // transmit timestamp
        ];

        let ntp = NtpViewer::new(&data);

        assert_eq!(ntp.leap_indicator(), NtpLeapIndicator::NoWarning);
        assert_eq!(ntp.version(), 4);
        assert_eq!(ntp.mode(), NtpMode::Server);
        assert_eq!(ntp.stratum(), 2);
        assert_eq!(ntp.poll(), 6);
        assert_eq!(ntp.precision(), -20);
        assert_eq!(ntp.root_delay(), 0x0001_0000);
        assert_eq!(ntp.root_dispersion(), 0x0002_0000);
        assert_eq!(ntp.reference_id(), b"LOCL");
        assert_eq!(ntp.reference_timestamp(), 0x0102_0304_0506_0708);
        assert_eq!(ntp.originate_timestamp(), 0x1112_1314_1516_1718);
        assert_eq!(ntp.receive_timestamp(), 0x2122_2324_2526_2728);
        assert_eq!(ntp.transmit_timestamp(), 0x3132_3334_3536_3738);
        assert_eq!(ntp.extension_bytes(), &[]);
    }

    #[test]
    fn ntp_viewer_mut() {
        let mut data: [u8; 48] = [0; 48];

        let mut ntp = NtpViewer::new(&mut data);
        ntp.leap_indicator_mut().set(NtpLeapIndicator::Alarm);
        ntp.version_mut().set(4);
        ntp.mode_mut().set(NtpMode::Client);
        ntp.stratum_mut().set(1);
        ntp.poll_mut().set(6);
        ntp.precision_mut().set(-20);
        ntp.root_delay_mut().set(0x0001_0000);
        ntp.root_dispersion_mut().set(0x0002_0000);
        ntp.reference_id_mut().copy_from_slice(b"GPS\0");
        ntp.reference_timestamp_mut().set(0x0102_0304_0506_0708);
        ntp.originate_timestamp_mut().set(0x1112_1314_1516_1718);
        ntp.receive_timestamp_mut().set(0x2122_2324_2526_2728);
        ntp.transmit_timestamp_mut().set(0x3132_3334_3536_3738);

        assert_eq!(
            data,
            [
                0xe3, // li: alarm, version: 4, mode: client
                0x01, // stratum
                0x06, // poll
                0xec, // precision: -20
                0x00, 0x01, 0x00, 0x00, // root delay
                0x00, 0x02, 0x00, 0x00, // root dispersion
                b'G', b'P', b'S', 0x00, // reference id
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
                0x17, 0x18, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x31, 0x32, 0x33, 0x34,
                0x35, 0x36, 0x37, 0x38,
            ]
        );
    }

    #[test]
    fn parse_ethernet_ipv4_udp_ntp_packet() {
        let data: [u8; 90] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // destination MAC
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, // source MAC
            0x08, 0x00, // EtherType: IPv4
            0x45, // version + ihl
            0x00, // dscp + ecn
            0x00, 0x4c, // total length
            0x00, 0x00, // identification
            0x00, 0x00, // flags + fragment offset
            0x40, // ttl
            0x11, // protocol: UDP
            0x00, 0x00, // checksum
            10, 0, 1, 1, // source IP
            10, 0, 1, 2, // destination IP
            0x00, 0x7b, // source port 123
            0x30, 0x39, // destination port 12345
            0x00, 0x38, // length
            0x00, 0x00, // checksum
            0x24, // li: none, version: 4, mode: server
            0x02, // stratum
            0x06, // poll
            0xec, // precision: -20
            0x00, 0x01, 0x00, 0x00, // root delay
            0x00, 0x02, 0x00, 0x00, // root dispersion
            b'L', b'O', b'C', b'L', // reference id
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
            0x17, 0x18, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x31, 0x32, 0x33, 0x34,
            0x35, 0x36, 0x37, 0x38,
        ];

        let mut packet = Packet::new(&data);
        packet.parse::<Eth>(Default::default());

        let ntp = packet.layer_viewer(Ntp).expect("NTP layer not found");
        assert_eq!(ntp.version(), 4);
        assert_eq!(ntp.mode(), NtpMode::Server);
        assert_eq!(ntp.stratum(), 2);
        assert_eq!(ntp.precision(), -20);
        assert_eq!(ntp.transmit_timestamp(), 0x3132_3334_3536_3738);
    }
}
