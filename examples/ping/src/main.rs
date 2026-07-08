use std::{
    io::ErrorKind,
    mem::MaybeUninit,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    time::{Duration, Instant},
};

use anyhow::{Context, bail};
use clap::Parser;
use maja::{
    icmp_echo, ipv4,
    packet::{
        Packet,
        layer::{
            icmp::{Icmp, IcmpType, IcmpViewer},
            ip::v4::Ipv4,
        },
    },
    raw,
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

/// Send IPv4 ICMP echo requests crafted by maja.
///
/// This is intentionally a small subset of the well-known `ping` utility. It
/// supports only IPv4 destinations and requires raw-socket privileges on common
/// operating systems.
#[derive(Debug, Parser)]
#[command(version, about, long_about)]
struct Cli {
    /// Number of ICMP echo requests to send.
    ///
    /// If omitted, requests are sent until the process is interrupted.
    #[arg(short = 'c', long)]
    count: Option<u64>,

    /// IPv4 destination address.
    destination: Ipv4Addr,
}

/// Raw IPv4 ICMP socket used to send crafted packets and receive replies.
struct RawIcmpSocket {
    socket: Socket,
}

impl RawIcmpSocket {
    /// Open a raw ICMP socket configured to accept full IPv4 packets.
    fn open(timeout: Duration) -> anyhow::Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
            .context("open raw ICMP socket; try running with CAP_NET_RAW or root privileges")?;
        socket
            .set_header_included_v4(true)
            .context("enable IP_HDRINCL")?;
        socket
            .set_read_timeout(Some(timeout))
            .context("set receive timeout")?;
        Ok(Self { socket })
    }

    /// Send one fully crafted IPv4 packet to `destination`.
    fn send_to(&self, destination: Ipv4Addr, packet: &[u8]) -> anyhow::Result<()> {
        let addr = SockAddr::from(SocketAddrV4::new(destination, 0));
        let written = self
            .socket
            .send_to(packet, &addr)
            .context("send ICMP echo request")?;
        if written != packet.len() {
            bail!(
                "short raw socket send: wrote {written} of {} bytes",
                packet.len()
            );
        }
        Ok(())
    }

    /// Receive one raw IPv4 packet.
    fn recv(&self, buffer: &mut [u8]) -> anyhow::Result<Option<usize>> {
        let mut uninit = vec![MaybeUninit::<u8>::uninit(); buffer.len()];
        match self.socket.recv(&mut uninit) {
            Ok(read) => {
                // SAFETY: `socket2::Socket::recv` returns the number of bytes
                // initialized in the beginning of the provided buffer.
                let initialized =
                    unsafe { std::slice::from_raw_parts(uninit.as_ptr().cast::<u8>(), read) };
                buffer[..read].copy_from_slice(initialized);
                Ok(Some(read))
            }
            Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                Ok(None)
            }
            Err(err) => Err(err).context("receive ICMP packet"),
        }
    }
}

#[derive(Debug)]
struct Reply {
    bytes: usize,
    ttl: u8,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let source = local_ipv4_for(cli.destination).context("select source IPv4 address")?;
    let socket = RawIcmpSocket::open(Duration::from_secs(1))?;
    let identifier = std::process::id() as u16;
    let payload = b"maja ping";
    let mut transmitted = 0u64;
    let mut received = 0u64;

    println!(
        "PING {} from {}: {} data bytes",
        cli.destination,
        source,
        payload.len()
    );

    while should_send_more(cli.count, transmitted) {
        let sequence = transmitted.wrapping_add(1) as u16;
        let packet = craft_echo_request(source, cli.destination, identifier, sequence, payload)?;
        let sent_at = Instant::now();
        socket.send_to(cli.destination, &packet)?;
        transmitted += 1;

        match receive_reply(&socket, cli.destination, identifier, sequence)? {
            Some(reply) => {
                received += 1;
                println!(
                    "{} bytes from {}: icmp_seq={} ttl={} time={:.3} ms",
                    reply.bytes,
                    cli.destination,
                    sequence,
                    reply.ttl,
                    sent_at.elapsed().as_secs_f64() * 1000.0
                );
            }
            None => {
                println!("Request timeout for icmp_seq={sequence}");
            }
        }

        if should_send_more(cli.count, transmitted) {
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    let loss = if transmitted == 0 {
        0.0
    } else {
        (transmitted - received) as f64 * 100.0 / transmitted as f64
    };
    println!(
        "\n--- {} ping statistics ---\n{} packets transmitted, {} received, {:.1}% packet loss",
        cli.destination, transmitted, received, loss
    );

    Ok(())
}

/// Return whether the sender should transmit another echo request.
fn should_send_more(count: Option<u64>, transmitted: u64) -> bool {
    match count {
        Some(count) => transmitted < count,
        None => true,
    }
}

/// Determine the local IPv4 address the OS would route toward `destination`.
fn local_ipv4_for(destination: Ipv4Addr) -> anyhow::Result<Ipv4Addr> {
    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))?;
    socket.connect(SocketAddrV4::new(destination, 33434))?;
    match socket.local_addr()? {
        SocketAddr::V4(addr) => Ok(*addr.ip()),
        SocketAddr::V6(_) => bail!("expected IPv4 local address"),
    }
}

/// Craft one full IPv4 ICMP echo request packet.
fn craft_echo_request(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    identifier: u16,
    sequence: u16,
    payload: &'static [u8],
) -> anyhow::Result<Vec<u8>> {
    (ipv4!(src: source, dst: destination, id: sequence)
        / icmp_echo!(request, id: identifier, seq: sequence)
        / raw!(payload))
    .to_bytes()
    .context("craft IPv4 ICMP echo request")
}

/// Receive packets until a matching ICMP echo reply arrives or the socket
/// timeout fires.
fn receive_reply(
    socket: &RawIcmpSocket,
    destination: Ipv4Addr,
    identifier: u16,
    sequence: u16,
) -> anyhow::Result<Option<Reply>> {
    let mut buffer = [0u8; 2048];

    loop {
        let Some(len) = socket.recv(&mut buffer)? else {
            return Ok(None);
        };
        let Some(reply) = parse_reply(&buffer[..len], destination, identifier, sequence) else {
            continue;
        };
        return Ok(Some(reply));
    }
}

/// Parse a raw IPv4 packet and return a reply when it matches this ping flow.
fn parse_reply(
    bytes: &[u8],
    destination: Ipv4Addr,
    identifier: u16,
    sequence: u16,
) -> Option<Reply> {
    let mut packet = Packet::new(bytes);
    packet.try_parse::<Ipv4>(Default::default()).ok()?;

    let ipv4 = packet.layer_viewer(Ipv4)?;
    if ipv4.src().get() != destination {
        return None;
    }

    let total_len = usize::from(ipv4.total_length().get());
    let header_len = ipv4.header_len();
    let icmp_bytes = bytes.get(header_len..total_len)?;
    let icmp_message = IcmpViewer::new(icmp_bytes);
    if !icmp_message.validate_checksum() {
        return None;
    }

    let icmp = packet.layer_viewer(Icmp)?;
    if icmp.message_type().get() != IcmpType::EchoReply
        || icmp.identifier().get() != identifier
        || icmp.sequence().get() != sequence
    {
        return None;
    }

    Some(Reply {
        bytes: total_len,
        ttl: ipv4.ttl().get(),
    })
}
