//! DHCP option parsing.

use num_enum::{FromPrimitive, IntoPrimitive};
use strum::{AsRefStr, Display, EnumString};

use crate::impl_target;

/// DHCP option code values.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    // num_enum traits
    FromPrimitive,
    IntoPrimitive,
    // strum traits
    AsRefStr,
    Display,
    EnumString,
)]
#[repr(u8)]
#[non_exhaustive]
pub enum DhcpOptionCode {
    /// Padding.
    Pad = 0,
    /// Subnet mask.
    SubnetMask = 1,
    /// Router.
    Router = 3,
    /// Domain name server.
    DomainNameServer = 6,
    /// Host name.
    HostName = 12,
    /// Domain name.
    DomainName = 15,
    /// Requested IP address.
    RequestedIpAddress = 50,
    /// IP address lease time.
    IpAddressLeaseTime = 51,
    /// DHCP message type.
    MessageType = 53,
    /// Server identifier.
    ServerIdentifier = 54,
    /// Parameter request list.
    ParameterRequestList = 55,
    /// Renewal time value.
    RenewalTime = 58,
    /// Rebinding time value.
    RebindingTime = 59,
    /// Vendor class identifier.
    VendorClassIdentifier = 60,
    /// Client identifier.
    ClientIdentifier = 61,
    /// Unknown option code.
    #[num_enum(catch_all)]
    Unknown(u8),
    /// End of options.
    End = 255,
}

impl_target!(frominto, DhcpOptionCode, u8);

/// Parsed DHCP option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpOption<'a> {
    /// Padding.
    Pad,
    /// End of options.
    End,
    /// Option with code, length, and data bytes.
    Option {
        /// Option code.
        code: DhcpOptionCode,
        /// Option length.
        len: u8,
        /// Option data.
        data: &'a [u8],
    },
    /// Malformed option bytes.
    Malformed {
        /// Raw option code.
        code: u8,
        /// Remaining malformed bytes.
        bytes: &'a [u8],
    },
}

/// Iterator over DHCP options.
#[derive(Debug, Clone)]
pub struct DhcpOptions<'a> {
    bytes: &'a [u8],
    offset: usize,
    done: bool,
}

impl<'a> DhcpOptions<'a> {
    /// Create a new DHCP option iterator.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            offset: 0,
            done: false,
        }
    }
}

impl<'a> Iterator for DhcpOptions<'a> {
    type Item = DhcpOption<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.offset >= self.bytes.len() {
            return None;
        }

        let start = self.offset;
        let code = self.bytes[start];

        match DhcpOptionCode::from(code) {
            DhcpOptionCode::Pad => {
                self.offset += 1;
                Some(DhcpOption::Pad)
            }
            DhcpOptionCode::End => {
                self.offset += 1;
                self.done = true;
                Some(DhcpOption::End)
            }
            option_code => {
                let Some(&len) = self.bytes.get(start + 1) else {
                    self.done = true;
                    return Some(DhcpOption::Malformed {
                        code,
                        bytes: &self.bytes[start..],
                    });
                };

                let end = start + 2 + len as usize;
                if end > self.bytes.len() {
                    self.done = true;
                    return Some(DhcpOption::Malformed {
                        code,
                        bytes: &self.bytes[start..],
                    });
                }

                self.offset = end;
                Some(DhcpOption::Option {
                    code: option_code,
                    len,
                    data: &self.bytes[start + 2..end],
                })
            }
        }
    }
}
