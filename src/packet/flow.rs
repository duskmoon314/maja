//! Flow identifiers for grouping related packets.
//!
//! A [`FlowId`](crate::packet::flow::FlowId) can represent an address-only key,
//! a 2-tuple, or a full transport 5-tuple. The const generic controls whether
//! endpoints are canonicalized so both directions of the same conversation
//! compare equal.

use std::net::IpAddr;

use crate::packet::layer::ip::protocol::IpProtocol;

/// # FlowId
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FlowId<const SYMMETRIC: bool = true> {
    /// Single IpAddress
    Ip(IpAddr),

    /// 2-tuple: SrcIp, DstIp
    Tuple2(IpAddr, IpAddr),

    /// 3-tuple: Src Ip address + Dst Ip address + Protocol
    Tuple3(IpAddr, IpAddr, IpProtocol),

    /// 4-tuple: Src Ip address + Dst Ip address + Src Port + Dst Port
    Tuple4(IpAddr, IpAddr, u16, u16),

    /// 5-tuple: Src Ip address + Dst Ip address + Src Port + Dst Port + Protocol
    Tuple5(IpAddr, IpAddr, u16, u16, IpProtocol),
}

/// Direction-agnostic flow key.
///
/// Endpoint order is normalized for tuple variants, so request and response
/// packets produce the same identifier.
pub type FlowIdSymmetric = FlowId<true>;
/// Direction-sensitive flow key.
///
/// Endpoint order is preserved, so opposite directions produce distinct
/// identifiers.
pub type FlowIdAsymmetric = FlowId<false>;

impl<const SYMMETRIC: bool> FlowId<SYMMETRIC> {
    /// Return whether this type normalizes endpoint order.
    pub fn is_symmetric(&self) -> bool {
        SYMMETRIC
    }

    /// Construct a flow identifier from any supported tuple shape.
    pub fn new(tuple: impl Into<FlowId<SYMMETRIC>>) -> Self {
        tuple.into()
    }
}

impl<const SYMMETRIC: bool> From<IpAddr> for FlowId<SYMMETRIC> {
    fn from(ip: IpAddr) -> Self {
        FlowId::Ip(ip)
    }
}

impl<const SYMMETRIC: bool> From<&IpAddr> for FlowId<SYMMETRIC> {
    fn from(ip: &IpAddr) -> Self {
        FlowId::Ip(*ip)
    }
}

impl From<(IpAddr, IpAddr)> for FlowId<false> {
    fn from((src, dst): (IpAddr, IpAddr)) -> Self {
        FlowId::Tuple2(src, dst)
    }
}

impl From<(IpAddr, IpAddr)> for FlowId<true> {
    fn from((src, dst): (IpAddr, IpAddr)) -> Self {
        if src < dst {
            FlowId::Tuple2(src, dst)
        } else {
            FlowId::Tuple2(dst, src)
        }
    }
}

impl From<(IpAddr, IpAddr, IpProtocol)> for FlowId<false> {
    fn from((src, dst, proto): (IpAddr, IpAddr, IpProtocol)) -> Self {
        FlowId::Tuple3(src, dst, proto)
    }
}

impl From<(IpAddr, IpAddr, IpProtocol)> for FlowId<true> {
    fn from((src, dst, proto): (IpAddr, IpAddr, IpProtocol)) -> Self {
        if src < dst {
            FlowId::Tuple3(src, dst, proto)
        } else {
            FlowId::Tuple3(dst, src, proto)
        }
    }
}

impl From<(IpAddr, IpAddr, u16, u16)> for FlowId<false> {
    fn from((src, dst, src_port, dst_port): (IpAddr, IpAddr, u16, u16)) -> Self {
        FlowId::Tuple4(src, dst, src_port, dst_port)
    }
}

impl From<(IpAddr, IpAddr, u16, u16)> for FlowId<true> {
    fn from((src, dst, src_port, dst_port): (IpAddr, IpAddr, u16, u16)) -> Self {
        if (src, src_port) <= (dst, dst_port) {
            FlowId::Tuple4(src, dst, src_port, dst_port)
        } else {
            FlowId::Tuple4(dst, src, dst_port, src_port)
        }
    }
}

impl<Addr: Into<IpAddr>, Port: Into<u16>, Protocol: Into<IpProtocol>>
    From<(Addr, Addr, Port, Port, Protocol)> for FlowId<false>
{
    fn from((src, dst, src_port, dst_port, proto): (Addr, Addr, Port, Port, Protocol)) -> Self {
        FlowId::Tuple5(
            src.into(),
            dst.into(),
            src_port.into(),
            dst_port.into(),
            proto.into(),
        )
    }
}

impl<Addr: Into<IpAddr>, Port: Into<u16>, Protocol: Into<IpProtocol>>
    From<(Addr, Addr, Port, Port, Protocol)> for FlowId<true>
{
    fn from((src, dst, src_port, dst_port, proto): (Addr, Addr, Port, Port, Protocol)) -> Self {
        let src_ip = src.into();
        let dst_ip = dst.into();
        let src_port = src_port.into();
        let dst_port = dst_port.into();
        let proto = proto.into();

        if (src_ip, src_port) <= (dst_ip, dst_port) {
            FlowId::Tuple5(src_ip, dst_ip, src_port, dst_port, proto)
        } else {
            FlowId::Tuple5(dst_ip, src_ip, dst_port, src_port, proto)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_id() {
        let ip1 = IpAddr::from([192, 168, 1, 1]);
        let ip2 = IpAddr::from([192, 168, 1, 2]);
        let port_1 = 1234u16;
        let port_2 = 5678u16;
        let protocol = IpProtocol::Tcp;

        let flow1 = FlowIdSymmetric::new((ip1, ip2, port_1, port_2, protocol));
        let flow2 = FlowIdSymmetric::new((ip2, ip1, port_2, port_1, protocol));

        assert_eq!(flow1, flow2);
    }

    #[test]
    fn symmetric_flow_id_orders_same_ip_by_port() {
        let ip = IpAddr::from([192, 168, 1, 1]);
        let port_1 = 1234u16;
        let port_2 = 5678u16;
        let protocol = IpProtocol::Tcp;

        let flow1 = FlowIdSymmetric::new((ip, ip, port_1, port_2, protocol));
        let flow2 = FlowIdSymmetric::new((ip, ip, port_2, port_1, protocol));

        assert_eq!(flow1, flow2);
    }
}
