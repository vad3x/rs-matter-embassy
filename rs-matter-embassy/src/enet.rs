//! Network interface: `EnetNetif` - a `Netif` trait implementation for `embassy-net`
//! UDP: A `UdpBind` trait implementation for `embassy-net`

use core::cell::Cell;
use core::net::Ipv6Addr;
use core::task::Context;

use embassy_futures::select::select;

use embassy_net::driver::{
    Capabilities, Driver, HardwareAddress as DriverHardwareAddress, LinkState, RxToken, TxToken,
};
use embassy_net::{
    Config, ConfigV6, HardwareAddress, IpAddress, Ipv6Cidr, Runner, Stack, StackResources,
    StaticConfigV6,
};

use embassy_time::{Duration, Timer};

use crate::matter::dm::clusters::gen_diag::{InterfaceTypeEnum, NetifDiag, NetifInfo};
use crate::matter::dm::networks::NetChangeNotif;
use crate::matter::error::Error;
use crate::matter::transport::network::{MAX_RX_PACKET_SIZE, MAX_TX_PACKET_SIZE};
use crate::matter::utils::sync::blocking::Mutex;
use crate::matter::utils::sync::DynBase;
use crate::stack::nal::noop::NoopNet;
use crate::stack::nal::NetStack;

/// Re-export the `edge-nal-embassy` crate
pub use edge_nal_embassy::*;

/// Re-export the `embassy-net` crate
pub mod net {
    pub use ::embassy_net::*;
}

/// The minimum number of sockets that should be configured in the `embassy-net` `StackResources`:
/// The two UDP sockets used by the Matter stack, plus extra 2 for DHCP + DNS
// TODO: Make it configurable with a feature
pub const ENET_MIN_SOCKET_SET: usize = ENET_MAX_UDP_SOCKETS + 2;

/// A type alias for the `UdpBuffers` type configured with the minimum number of UDP socket buffers
/// sufficient for the operation of the Matter stack
pub type EnetMatterUdpBuffers = UdpBuffers<
    ENET_MAX_UDP_SOCKETS,
    MAX_TX_PACKET_SIZE,
    MAX_RX_PACKET_SIZE,
    ENET_MAX_UDP_META_DATA,
>;

/// A type alias for the `StackResources` type configured with the minimum number of sockets
/// sufficient for the operation of the Matter stack
pub type EnetMatterStackResources = StackResources<ENET_MIN_SOCKET_SET>;

/// The maximum number of sockets that the Matter stack would use:
/// - One, for the UDP socket used by the Matter protocol
/// - Another, for the UDP socket used by the mDNS responder
// TODO: Make it configurable with a feature
const ENET_MAX_UDP_SOCKETS: usize = 2;
/// The max number of meta data buffers that the Matter stack would use
const ENET_MAX_UDP_META_DATA: usize = 4;

/// The MAC address used for mDNS multicast queries over IPv4
///
/// Useful with wifi stack implementations (i.e. cyw43) that require explicit
/// allowlisting of the multicast MAC addresses they should be listening on.
pub const MDNS_MULTICAST_MAC_IPV4: [u8; 6] = [0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb];

/// The MAC address used for mDNS multicast queries over IPv6
///
/// Useful with wifi stack implementations (i.e. cyw43) that require explicit
/// allowlisting of the multicast MAC addresses they should be listening on.
pub const MDNS_MULTICAST_MAC_IPV6: [u8; 6] = [0x33, 0x33, 0x00, 0x00, 0x00, 0xfb];

const TIMEOUT_PERIOD_SECS: u8 = 5;

/// A `Netif` trait implementation for `embassy-net`
pub struct EnetNetif<'d> {
    stack: Stack<'d>,
    up: Mutex<Cell<bool>>,
    netif_type: InterfaceTypeEnum,
}

impl<'d> EnetNetif<'d> {
    /// Create a new `EmbassyNetif` instance
    pub const fn new(stack: Stack<'d>, netif_type: InterfaceTypeEnum) -> Self {
        Self {
            stack,
            up: Mutex::new(Cell::new(false)),
            netif_type,
        }
    }
}

impl DynBase for EnetNetif<'_> {}

impl NetifDiag for EnetNetif<'_> {
    fn netifs(&self, f: &mut dyn FnMut(&NetifInfo) -> Result<(), Error>) -> Result<(), Error> {
        let v4 = self.stack.config_v4();
        let v6 = self.stack.config_v6();

        let mut hw_addr = [0; 8];
        match self.stack.hardware_address() {
            HardwareAddress::Ethernet(addr) => hw_addr[..6].copy_from_slice(&addr.0),
            #[allow(unreachable_patterns)]
            _ => (),
        }

        f(&NetifInfo {
            name: "enet",
            operational: self.stack.is_link_up(),
            offprem_svc_reachable_ipv4: None,
            offprem_svc_reachable_ipv6: None,
            hw_addr: &hw_addr,
            ipv4_addrs: if let Some(addrs) = v4.map(|v4| [v4.address.address()]).as_ref() {
                addrs.as_slice()
            } else {
                &[]
            },
            ipv6_addrs: if let Some(addrs) = v6.map(|v6| [v6.address.address()]).as_ref() {
                addrs.as_slice()
            } else {
                &[]
            },
            netif_type: self.netif_type,
            netif_index: 0, // Not used on baremetal
        })?;

        Ok(())
    }
}

impl NetChangeNotif for EnetNetif<'_> {
    async fn wait_changed(&self) {
        // Embassy does have a `wait_config_up/down` but no `wait_config_change`
        // Use a timer as a workaround

        if self.up.lock(|up| up.get()) {
            select(
                self.stack.wait_config_down(),
                Timer::after(Duration::from_secs(TIMEOUT_PERIOD_SECS as _)),
            )
            .await;
        } else {
            select(
                self.stack.wait_config_up(),
                Timer::after(Duration::from_secs(TIMEOUT_PERIOD_SECS as _)),
            )
            .await;
        }

        self.up.lock(|up| up.set(self.stack.is_config_up()));
    }
}

/// Create an `embassy-net` stack suitable for the `rs-matter` stack.
///
/// This does two things beyond the bare [`embassy_net::new`]:
///
/// 1. Subscribes the interface to the IPv6 **solicited-node multicast group**
///    (`ff02::1:ffXX:XXXX`) derived from the link-local address, so that other
///    nodes can resolve the device via Neighbor Solicitation.
/// 2. Wraps the supplied driver in [`Mldv1ConvertingDriver`], which rewrites
///    every outgoing **MLDv2 Report** (ICMPv6 type 143, sent to `ff02::16`)
///    into an equivalent **MLDv1 Report** (ICMPv6 type 131, sent to the group
///    address itself) before handing it to the radio.
///
/// **Why MLDv1?** smoltcp emits MLDv2 only. Many consumer/SMB APs — notably
/// TP-Link Omada with "Multicast-to-Unicast Conversion" enabled — only snoop
/// MLDv1 and silently drop MLDv2. Without a recognised Membership Report the
/// AP never learns that this station has joined `ff02::1:ffXX:XXXX`, so it
/// drops every Neighbor Solicitation aimed at us. IPv6 unicast then appears
/// to work intermittently (often just long enough for PASE → first CASE)
/// before silently breaking — typically right after the commissioner's
/// `AddNOC` for a second fabric, when a fresh ND resolution is required.
///
/// The C++ ESP-IDF firmware uses lwIP, which sends MLDv1 by default; this is
/// why the same hardware works on the same AP under C++ but not under Rust.
pub fn create_enet_stack<const N: usize, D: Driver>(
    driver: D,
    seed: u64,
    resources: &mut StackResources<N>,
) -> (Stack<'_>, Runner<'_, Mldv1ConvertingDriver<D>>) {
    let config = create_enet_config(&driver);

    let (stack, runner) = net::new(Mldv1ConvertingDriver::new(driver), config, resources, seed);

    if let Some(v6) = stack.config_v6() {
        let solicited = solicited_node_multicast_ipv6(&v6.address.address());
        let _ = stack.join_multicast_group(IpAddress::Ipv6(solicited));
    }

    (stack, runner)
}

/// Create a `Config` instance suitable for the `rs-matter` stack:
/// - Ipv6 enabled with a static configuration that uses the link-local address derived from the MAC address
/// - Ipv4 enabled with DHCPv4; structly speaking this is not necessary for the Matter stack, but it is
///   useful in that the `rs-matter` mDNS responder would also answer ipv4 queries
pub fn create_enet_config<D: Driver>(driver: &D) -> Config {
    let DriverHardwareAddress::Ethernet(mac) = driver.hardware_address() else {
        unreachable!();
    };

    let mut config = Config::dhcpv4(Default::default());
    config.ipv6 = ConfigV6::Static(StaticConfigV6 {
        address: Ipv6Cidr::new(create_link_local_ipv6(&mac), 10),
        gateway: None,
        dns_servers: heapless::Vec::new(),
    });

    config
}

/// Create a link-local IPv6 address from a MAC address.
pub fn create_link_local_ipv6(mac: &[u8; 6]) -> Ipv6Addr {
    Ipv6Addr::new(
        0xfe80,
        0,
        0,
        0,
        u16::from_be_bytes([mac[0] ^ 0x02, mac[1]]),
        u16::from_be_bytes([mac[2], 0xff]),
        u16::from_be_bytes([0xfe, mac[3]]),
        u16::from_be_bytes([mac[4], mac[5]]),
    )
}

/// Get the multicast MAC address corresponding to the given IPv6 link-local address.
///
/// Useful with Wifi stack implementations (i.e. cyw43) that require explicit
/// allowlisting of the multicast MAC addresses they should be listening on.
///
/// Note that the provided IP should be a link-local IP (fe80::/10) or else this
/// function would return a bogus result.
pub fn multicast_mac_for_link_local_ipv6(ip: &Ipv6Addr) -> [u8; 6] {
    let mut mac = [0x33, 0x33, 0xff, 0, 0, 0];
    mac[3..].copy_from_slice(&ip.octets()[13..]);

    mac
}

/// Compute the IPv6 **solicited-node multicast address** (`ff02::1:ffXX:XXXX`)
/// for a given unicast IPv6 address, per RFC 4291 §2.7.1.
///
/// The low-order 24 bits of the unicast address are copied into the low-order
/// 24 bits of the multicast address. A host MUST be a member of this group for
/// every unicast address it is assigned so that other nodes can resolve its
/// MAC via Neighbor Solicitation (RFC 4861 §7.2.1).
pub fn solicited_node_multicast_ipv6(addr: &Ipv6Addr) -> Ipv6Addr {
    let o = addr.octets();
    Ipv6Addr::new(
        0xff02,
        0,
        0,
        0,
        0,
        0x0001,
        0xff00 | (o[13] as u16),
        u16::from_be_bytes([o[14], o[15]]),
    )
}

// ---------------------------------------------------------------------------
// MLDv2 → MLDv1 outgoing conversion
// ---------------------------------------------------------------------------

/// An [`embassy_net::driver::Driver`] wrapper that rewrites outgoing MLDv2
/// Reports into MLDv1 Reports before they reach the radio.
///
/// All non-MLD traffic (and inbound traffic) is passed through unchanged. The
/// transformation is purely a TX-side fix for AP MLD-snooping compatibility;
/// see [`create_enet_stack`] for the rationale.
pub struct Mldv1ConvertingDriver<D> {
    inner: D,
}

impl<D> Mldv1ConvertingDriver<D> {
    pub const fn new(inner: D) -> Self {
        Self { inner }
    }
}

impl<D: Driver> Driver for Mldv1ConvertingDriver<D> {
    type RxToken<'a>
        = D::RxToken<'a>
    where
        Self: 'a;
    type TxToken<'a>
        = Mldv1ConvertingTxToken<D::TxToken<'a>>
    where
        Self: 'a;

    fn receive(&mut self, cx: &mut Context) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.inner
            .receive(cx)
            .map(|(rx, tx)| (rx, Mldv1ConvertingTxToken { inner: tx }))
    }

    fn transmit(&mut self, cx: &mut Context) -> Option<Self::TxToken<'_>> {
        self.inner
            .transmit(cx)
            .map(|tx| Mldv1ConvertingTxToken { inner: tx })
    }

    fn link_state(&mut self, cx: &mut Context) -> LinkState {
        self.inner.link_state(cx)
    }

    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities()
    }

    fn hardware_address(&self) -> DriverHardwareAddress {
        self.inner.hardware_address()
    }
}

/// TX token wrapper that intercepts the outgoing buffer just before the radio
/// consumes it and applies the MLDv2 → MLDv1 conversion in-place.
pub struct Mldv1ConvertingTxToken<T> {
    inner: T,
}

impl<T: TxToken> TxToken for Mldv1ConvertingTxToken<T> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        self.inner.consume(len, |buf| {
            let r = f(buf);
            convert_mldv2_to_mldv1(buf);
            r
        })
    }
}

/// In-place rewrite of an outgoing **single-record MLDv2 Report** (RFC 3810)
/// into an **MLDv1 Report** (RFC 2710) within an Ethernet frame.
///
/// smoltcp only ever emits single-record MLDv2 Reports as a side-effect of
/// `join_multicast_group` / `leave_multicast_group`, plus the periodic state
/// reporting. We rewrite each one to the older format the AP understands.
///
/// Layout transformation:
///
/// ```text
/// MLDv2 Report (Ethernet payload ≥ 36 B):    MLDv1 Report (28 B payload):
/// [0-5]   dst MAC  33:33:00:00:00:16          [0-5]   dst MAC  33:33:XX:XX:XX:XX (group)
/// [6-11]  src MAC  (unchanged)                [6-11]  src MAC  (unchanged)
/// [12-13] 0x86DD                              [12-13] 0x86DD
/// [14-53] IPv6 hdr (dst=ff02::16, len=36)     [14-53] IPv6 hdr (dst=group, len=32)
/// [54-61] HbH option header (router-alert)    [54-61] HbH option header (unchanged)
/// [62]    ICMPv6 type=143                     [62]    ICMPv6 type=131
/// [63]    code=0                              [63]    code=0
/// [64-65] checksum                            [64-65] checksum (recomputed)
/// [66-67] reserved                            [66-67] max response delay=0
/// [68-69] nr_records=1                        [68-69] reserved=0
/// [70]    record type                         [70-85] multicast address (16 B)
/// [71]    aux_len=0
/// [72-73] num_srcs=0
/// [74-89] multicast address (16 B)
/// ```
///
/// We deliberately leave the trailing bytes [86..90] as zero padding — the
/// IPv6 payload length is updated to 32, so the receiver ignores them.
fn convert_mldv2_to_mldv1(buf: &mut [u8]) {
    // Eth + IPv6 hdr + HbH + MLDv2 single-record = 90 bytes
    if buf.len() < 90 {
        return;
    }
    // Ethernet IPv6
    if buf[12] != 0x86 || buf[13] != 0xDD {
        return;
    }
    // IPv6 Next Header = 0 (Hop-by-Hop) — MLD always uses HbH router alert
    if buf[20] != 0 {
        return;
    }
    // HbH Next Header = 58 (ICMPv6)
    if buf[54] != 58 {
        return;
    }
    // ICMPv6 type = 143 (MLDv2 Report)
    if buf[62] != 143 {
        return;
    }

    let mut mcast_addr = [0u8; 16];
    mcast_addr.copy_from_slice(&buf[74..90]);

    // Destination MAC: 33:33 + low 32 bits of the multicast IPv6 address
    buf[0] = 0x33;
    buf[1] = 0x33;
    buf[2..6].copy_from_slice(&mcast_addr[12..16]);

    // Destination IPv6 = the multicast group itself
    buf[38..54].copy_from_slice(&mcast_addr);

    // IPv6 payload length = HbH(8) + ICMPv6 MLDv1(24) = 32
    buf[18] = 0;
    buf[19] = 32;

    // ICMPv6 header
    buf[62] = 131; // MLDv1 Membership Report
    buf[63] = 0; // code
    buf[64] = 0; // checksum (zeroed for calculation)
    buf[65] = 0;
    buf[66] = 0; // max response delay = 0 (reports ignore this field)
    buf[67] = 0;
    buf[68] = 0; // reserved
    buf[69] = 0;
    buf[70..86].copy_from_slice(&mcast_addr);

    // Zero the trailing 4 bytes of the original MLDv2 record so they don't
    // leak into anything that might inspect the full frame buffer.
    buf[86..90].fill(0);

    let cksum = icmpv6_checksum_mldv1(buf);
    buf[64] = (cksum >> 8) as u8;
    buf[65] = (cksum & 0xFF) as u8;
}

/// Compute the ICMPv6 checksum (RFC 4443 §2.3) for a 24-byte MLDv1 message
/// at offset [62..86] in the given Ethernet frame.
///
/// Pseudo-header is src IPv6 (16) + dst IPv6 (16) + upper-layer length (4) +
/// next header (4 with 3 zero bytes). The caller must have zeroed the
/// checksum field at [64..66] before calling.
fn icmpv6_checksum_mldv1(buf: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    let mut i = 22;
    while i < 38 {
        sum += u16::from_be_bytes([buf[i], buf[i + 1]]) as u32;
        i += 2;
    }
    i = 38;
    while i < 54 {
        sum += u16::from_be_bytes([buf[i], buf[i + 1]]) as u32;
        i += 2;
    }
    sum += 24_u32; // upper-layer length
    sum += 58_u32; // next header = ICMPv6
    i = 62;
    while i < 86 {
        sum += u16::from_be_bytes([buf[i], buf[i + 1]]) as u32;
        i += 2;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// An implementation of `NetStack` for the `embassy-net` stack
// TODO: Implement optional TCP support with a feature flag
#[derive(Copy, Clone)]
pub struct EnetStack<'a> {
    udp: Udp<'a>,
    dns: Dns<'a>,
}

impl<'a> EnetStack<'a> {
    /// Create a new `EnetStack` instance
    pub fn new(stack: Stack<'a>, buffers: &'a EnetMatterUdpBuffers) -> Self {
        Self {
            udp: Udp::new(stack, buffers),
            dns: Dns::new(stack),
        }
    }
}

impl<'a> NetStack for EnetStack<'a> {
    type UdpBind<'t>
        = Udp<'t>
    where
        Self: 't;

    type UdpConnect<'t>
        = NoopNet
    where
        Self: 't;

    type TcpBind<'t>
        = NoopNet
    where
        Self: 't;

    type TcpConnect<'t>
        = NoopNet
    where
        Self: 't;

    type Dns<'t>
        = Dns<'t>
    where
        Self: 't;

    fn udp_bind(&self) -> Option<Self::UdpBind<'_>> {
        Some(self.udp)
    }

    fn udp_connect(&self) -> Option<Self::UdpConnect<'_>> {
        None
    }

    fn tcp_bind(&self) -> Option<Self::TcpBind<'_>> {
        None
    }

    fn tcp_connect(&self) -> Option<Self::TcpConnect<'_>> {
        None
    }

    fn dns(&self) -> Option<Self::Dns<'_>> {
        Some(self.dns)
    }
}

#[cfg(test)]
mod test {
    use core::net::Ipv6Addr;

    #[test]
    fn test() {
        assert_eq!(
            super::create_link_local_ipv6(&[0x52, 0x74, 0xf2, 0xb1, 0xa8, 0x7f]).octets(),
            [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x50, 0x74, 0xf2, 0xff, 0xfe, 0xb1, 0xa8, 0x7f]
        );
    }

    #[test]
    fn solicited_node_multicast_ipv6_matches_rfc4291() {
        // RFC 4291 §2.7.1: copies low 24 bits of the unicast address into ff02::1:ff00:0/104
        let link_local =
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0x9e13, 0x9eff, 0xfed7, 0xbda8);
        assert_eq!(
            super::solicited_node_multicast_ipv6(&link_local),
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0x0001, 0xffd7, 0xbda8),
        );
    }

    #[test]
    fn solicited_node_multicast_mac_matches_low_24_bits() {
        // Sanity-check that the solicited-node IPv6 and its multicast MAC stay aligned:
        // both must end in the low 24 bits of the unicast address.
        let link_local =
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0x9e13, 0x9eff, 0xfed7, 0xbda8);
        let solicited = super::solicited_node_multicast_ipv6(&link_local);
        let mac = super::multicast_mac_for_link_local_ipv6(&link_local);

        assert_eq!(&solicited.octets()[13..], &mac[3..]);
    }

    /// Build a realistic 90-byte single-record MLDv2 Report frame:
    /// joining ff02::1:ffd7:bda8 from fe80::9e13:9eff:fed7:bda8.
    fn make_mldv2_join_frame() -> [u8; 90] {
        let mut f = [0u8; 90];
        // Ethernet header
        f[0..6].copy_from_slice(&[0x33, 0x33, 0x00, 0x00, 0x00, 0x16]); // dst ff02::16
        f[6..12].copy_from_slice(&[0x9c, 0x13, 0x9e, 0xd7, 0xbd, 0xa8]);
        f[12] = 0x86;
        f[13] = 0xDD;
        // IPv6 header
        f[14] = 0x60;
        f[15] = 0;
        f[16] = 0;
        f[17] = 0;
        f[18] = 0;
        f[19] = 36; // payload len = HbH(8) + MLDv2(28)
        f[20] = 0; // NH = Hop-by-Hop
        f[21] = 1; // hop limit (MLD requires 1)
        f[22..38]
            .copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x9e, 0x13, 0x9e, 0xff, 0xfe, 0xd7, 0xbd, 0xa8]);
        f[38..54]
            .copy_from_slice(&[0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x16]);
        // Hop-by-Hop options: NH=58 (ICMPv6), len=0 (8 bytes), router-alert
        f[54] = 58;
        f[55] = 0;
        f[56] = 0x05; // router alert option type
        f[57] = 0x02;
        f[58] = 0;
        f[59] = 0;
        f[60] = 0x01; // PadN
        f[61] = 0;
        // ICMPv6 MLDv2 Report
        f[62] = 143;
        f[63] = 0;
        f[64] = 0; // checksum (don't care for the test)
        f[65] = 0;
        f[66] = 0; // reserved
        f[67] = 0;
        f[68] = 0; // nr_records hi
        f[69] = 1; // nr_records lo
        f[70] = 4; // record type: CHANGE_TO_EXCLUDE_MODE (treat as include for join)
        f[71] = 0; // aux data len
        f[72] = 0; // num srcs hi
        f[73] = 0;
        f[74..90]
            .copy_from_slice(&[0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0xd7, 0xbd, 0xa8]);
        f
    }

    #[test]
    fn mldv2_to_mldv1_converts_dest_mac_and_ip_to_group() {
        let mut frame = make_mldv2_join_frame();

        super::convert_mldv2_to_mldv1(&mut frame);

        // Destination MAC must become 33:33 + low 32 bits of the group address
        assert_eq!(frame[0..6], [0x33, 0x33, 0xff, 0xd7, 0xbd, 0xa8]);
        // Destination IPv6 must become the group itself
        assert_eq!(
            frame[38..54],
            [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0xd7, 0xbd, 0xa8]
        );
        // ICMPv6 type must be 131 (MLDv1 Membership Report)
        assert_eq!(frame[62], 131);
        // IPv6 payload length must be 32 (HbH 8 + MLDv1 24)
        assert_eq!(u16::from_be_bytes([frame[18], frame[19]]), 32);
        // Multicast address field in MLDv1 payload must match the group
        assert_eq!(
            frame[70..86],
            [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0xd7, 0xbd, 0xa8]
        );
    }

    #[test]
    fn mldv2_to_mldv1_writes_valid_icmpv6_checksum() {
        let mut frame = make_mldv2_join_frame();

        super::convert_mldv2_to_mldv1(&mut frame);

        // A correctly-checksummed ICMPv6 message verifies as 0 when summed with
        // its own checksum still in place.
        let mut verify = frame;
        // Recompute over the post-conversion frame with the checksum field in place.
        let computed_when_zeroed = {
            verify[64] = 0;
            verify[65] = 0;
            super::icmpv6_checksum_mldv1(&verify)
        };
        let written = u16::from_be_bytes([frame[64], frame[65]]);
        assert_eq!(written, computed_when_zeroed);
        // And the written checksum must be non-trivial (sanity).
        assert_ne!(written, 0);
    }

    #[test]
    fn convert_mldv2_to_mldv1_is_noop_for_non_mld_frame() {
        // A regular UDP-over-IPv6 frame should be left untouched.
        let mut frame = [0u8; 90];
        frame[12] = 0x86;
        frame[13] = 0xDD;
        frame[20] = 17; // NH = UDP, NOT Hop-by-Hop
        let before = frame;

        super::convert_mldv2_to_mldv1(&mut frame);

        assert_eq!(frame, before);
    }

    #[test]
    fn convert_mldv2_to_mldv1_is_noop_for_non_ipv6_frame() {
        // ARP / IPv4 / random ethertype must be left untouched.
        let mut frame = [0u8; 90];
        frame[12] = 0x08;
        frame[13] = 0x00; // IPv4
        let before = frame;

        super::convert_mldv2_to_mldv1(&mut frame);

        assert_eq!(frame, before);
    }
}
