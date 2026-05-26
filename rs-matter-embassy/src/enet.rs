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

/// The driver chain returned by [`create_enet_stack`].
///
/// The supplied driver `D` is wrapped twice:
///
/// 1. Innermost: [`Mldv1ConvertingDriver`] — rewrites every outgoing MLDv2
///    Report into an equivalent MLDv1 Report on the TX path.
/// 2. Outermost: [`NeighborLearningDriver`] — populates smoltcp's IPv6
///    neighbor cache from incoming unicast IPv6 frames via synthetic
///    Neighbor Solicitation injection on the RX path.
///
/// The wrappers are transparent on the path they do not touch, so the chain
/// is functionally equivalent to `D` for all non-MLD / non-IPv6 traffic.
pub type MatterEnetDriver<D> = NeighborLearningDriver<Mldv1ConvertingDriver<D>>;

/// Create an `embassy-net` stack suitable for the `rs-matter` stack.
///
/// This does three things beyond the bare [`embassy_net::new`]:
///
/// 1. Subscribes the interface to the IPv6 **solicited-node multicast group**
///    (`ff02::1:ffXX:XXXX`) derived from the link-local address, so that other
///    nodes can resolve the device via Neighbor Solicitation.
/// 2. Wraps the supplied driver in [`Mldv1ConvertingDriver`], which rewrites
///    every outgoing **MLDv2 Report** (ICMPv6 type 143, sent to `ff02::16`)
///    into an equivalent **MLDv1 Report** (ICMPv6 type 131, sent to the group
///    address itself) before handing it to the radio.
/// 3. Wraps the result again in [`NeighborLearningDriver`], which teaches
///    smoltcp's neighbor cache about peers from incoming unicast IPv6 data
///    frames by injecting synthetic Neighbor Solicitations on the RX path.
///
/// **Why MLDv1?** smoltcp emits MLDv2 only. Many consumer/SMB APs — notably
/// TP-Link Omada with "Multicast-to-Unicast Conversion" enabled — only snoop
/// MLDv1 and silently drop MLDv2. Without a recognised Membership Report the
/// AP never learns that this station has joined `ff02::1:ffXX:XXXX`, so it
/// drops every Neighbor Solicitation aimed at us.
///
/// **Why synthetic NS injection?** smoltcp learns IPv6 neighbor cache entries
/// only from NDP messages (NS/NA/RA), never from plain data frames — unlike
/// lwIP, which learns from any incoming packet. Combined with the AP issue
/// above, this means an outbound reply to a peer can hang for tens of seconds
/// waiting for a Neighbor Solicitation round trip that may never succeed. By
/// faking an inbound NS "from" each peer whose data frame we just received,
/// we install the `{peer_ipv6 → peer_mac}` mapping immediately and skip
/// resolution entirely on the reply path.
///
/// The C++ ESP-IDF firmware uses lwIP, which sends MLDv1 by default and
/// learns neighbors from any frame; this is why the same hardware works on
/// the same AP under C++ but not under Rust without these wrappers.
pub fn create_enet_stack<const N: usize, D: Driver>(
    driver: D,
    seed: u64,
    resources: &mut StackResources<N>,
) -> (Stack<'_>, Runner<'_, MatterEnetDriver<D>>) {
    let config = create_enet_config(&driver);

    let wrapped = NeighborLearningDriver::new(Mldv1ConvertingDriver::new(driver));
    let (stack, runner) = net::new(wrapped, config, resources, seed);

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

    log::info!(
        "MLDv2→MLDv1: rewrote outgoing Report for {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
        mcast_addr[0], mcast_addr[1], mcast_addr[2], mcast_addr[3],
        mcast_addr[4], mcast_addr[5], mcast_addr[6], mcast_addr[7],
        mcast_addr[8], mcast_addr[9], mcast_addr[10], mcast_addr[11],
        mcast_addr[12], mcast_addr[13], mcast_addr[14], mcast_addr[15],
    );
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

// ---------------------------------------------------------------------------
// Neighbor learning via synthetic NS injection (RX-side)
// ---------------------------------------------------------------------------

/// Length of a Neighbor Solicitation Ethernet frame carrying a Source
/// Link-Layer Address option: 14 (Eth) + 40 (IPv6) + 24 (ICMPv6 NS) +
/// 8 (option) = 86 bytes.
const NDP_FRAME_LEN: usize = 86;

/// An [`embassy_net::driver::Driver`] wrapper that populates smoltcp's
/// neighbor cache from incoming unicast IPv6 data frames.
///
/// **Why?** smoltcp only learns IPv6 neighbor cache entries from NDP
/// messages (NS / NA / RA), never from regular data frames. lwIP — used by
/// C++ ESP-IDF — learns from any incoming packet, which is why the same
/// hardware "just works" under C++ but not under Rust.
///
/// Without this wrapper, when a remote peer (e.g. the Apple Home Hub
/// establishing a CASE session) sends us a unicast IPv6 frame, smoltcp:
///
/// 1. Receives and processes the frame.
/// 2. Builds a reply.
/// 3. Looks up the peer's MAC in the neighbor cache — finds nothing.
/// 4. Issues a Neighbor Solicitation to the peer's solicited-node multicast
///    group — which may be silently dropped by the AP (see
///    [`Mldv1ConvertingDriver`] for that part of the story).
/// 5. Reply never goes out; commissioning eventually times out.
///
/// This wrapper sidesteps the problem entirely: whenever a unicast IPv6
/// frame arrives, we record its `{src_mac, src_ipv6}`; on the very next
/// `Driver::receive` call we sacrifice one real RX frame and replace it
/// with a synthetic Neighbor Solicitation that appears to come from the
/// peer asking "who has our address?". smoltcp processes the NS, caches
/// the binding from the SLLA option, and replies with a Neighbor
/// Advertisement. From that point on, outbound packets to the peer go out
/// immediately with no resolution round trip.
///
/// The single dropped frame is harmless in practice — Matter MRP retries
/// it within ~200 ms, and on the retry the neighbor cache is populated so
/// the reply goes out immediately.
pub struct NeighborLearningDriver<D> {
    inner: D,
    our_mac: [u8; 6],
    our_ipv6: [u8; 16],
    pending: Cell<Option<([u8; 6], [u8; 16])>>,
}

impl<D: Driver> NeighborLearningDriver<D> {
    /// Wrap `inner`. Our MAC is read from `inner.hardware_address()`; our
    /// IPv6 is derived as the EUI-64 link-local from that MAC, matching the
    /// address [`create_enet_config`] installs on the stack.
    pub fn new(inner: D) -> Self {
        let our_mac = match inner.hardware_address() {
            DriverHardwareAddress::Ethernet(addr) => addr,
            #[allow(unreachable_patterns)]
            _ => [0; 6],
        };
        let our_ipv6 = create_link_local_ipv6(&our_mac).octets();
        Self {
            inner,
            our_mac,
            our_ipv6,
            pending: Cell::new(None),
        }
    }
}

impl<D: Driver> Driver for NeighborLearningDriver<D> {
    type RxToken<'a>
        = NeighborLearningRxToken<'a, D::RxToken<'a>>
    where
        Self: 'a;
    type TxToken<'a>
        = D::TxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self, cx: &mut Context) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // If a peer was queued on a previous RX, sacrifice one real RX slot
        // and feed smoltcp a synthetic NS so the {peer_ipv6 → peer_mac}
        // binding lands in the neighbor cache before any outbound packet
        // needs it.
        if let Some((remote_mac, remote_ipv6)) = self.pending.replace(None) {
            match self.inner.receive(cx) {
                Some((rx, tx)) => {
                    rx.consume(|_| {}); // drop the real frame, peer will retry
                    let mut frame = [0u8; NDP_FRAME_LEN];
                    construct_synthetic_ns(
                        &mut frame,
                        &self.our_mac,
                        &self.our_ipv6,
                        &remote_mac,
                        &remote_ipv6,
                    );
                    log::info!(
                        "NeighborLearn: inject synthetic NS for {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        remote_mac[0], remote_mac[1], remote_mac[2],
                        remote_mac[3], remote_mac[4], remote_mac[5],
                    );
                    return Some((
                        NeighborLearningRxToken {
                            inner: NeighborLearningRxTokenInner::Synthetic(frame),
                            pending: &self.pending,
                        },
                        tx,
                    ));
                }
                None => {
                    // No RX slot available right now — keep the entry pending
                    // for the next poll.
                    self.pending.set(Some((remote_mac, remote_ipv6)));
                    return None;
                }
            }
        }

        let (rx, tx) = self.inner.receive(cx)?;
        Some((
            NeighborLearningRxToken {
                inner: NeighborLearningRxTokenInner::Real(rx),
                pending: &self.pending,
            },
            tx,
        ))
    }

    fn transmit(&mut self, cx: &mut Context) -> Option<Self::TxToken<'_>> {
        self.inner.transmit(cx)
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

/// RX token wrapper used by [`NeighborLearningDriver`]. Either delivers a
/// real frame from the radio (and on the way through inspects the source
/// for neighbor learning) or a synthetic Neighbor Solicitation that the
/// driver itself constructed.
pub struct NeighborLearningRxToken<'a, T> {
    inner: NeighborLearningRxTokenInner<T>,
    pending: &'a Cell<Option<([u8; 6], [u8; 16])>>,
}

enum NeighborLearningRxTokenInner<T> {
    Real(T),
    Synthetic([u8; NDP_FRAME_LEN]),
}

impl<T: RxToken> RxToken for NeighborLearningRxToken<'_, T> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        match self.inner {
            NeighborLearningRxTokenInner::Real(inner) => {
                let pending = self.pending;
                inner.consume(|buf| {
                    queue_neighbor_from_frame(buf, pending);
                    f(buf)
                })
            }
            NeighborLearningRxTokenInner::Synthetic(mut frame) => f(&mut frame),
        }
    }
}

/// If `buf` is an inbound unicast IPv6 Ethernet frame from a real source,
/// stash its `{src_mac, src_ipv6}` in `pending` so the driver's next
/// `receive` call can inject a synthetic Neighbor Solicitation for it.
///
/// Skipped if:
/// - the frame is not IPv6 (EtherType ≠ 0x86DD),
/// - the destination MAC is multicast/broadcast (we only learn from frames
///   addressed to us),
/// - the source IPv6 is the unspecified address `::` (e.g. during DAD),
/// - a previous entry is still pending (we don't overwrite — the first
///   learning chance per cycle is good enough).
fn queue_neighbor_from_frame(buf: &[u8], pending: &Cell<Option<([u8; 6], [u8; 16])>>) {
    if buf.len() < 54 || buf[12] != 0x86 || buf[13] != 0xDD {
        return;
    }
    // Multicast bit set on destination MAC → not addressed to us alone.
    if buf[0] & 0x01 != 0 {
        return;
    }
    // Unspecified source IPv6 — nothing useful to learn.
    if buf[22..38] == [0u8; 16] {
        return;
    }
    if pending.get().is_some() {
        return;
    }

    let mut src_mac = [0u8; 6];
    src_mac.copy_from_slice(&buf[6..12]);
    let mut src_ipv6 = [0u8; 16];
    src_ipv6.copy_from_slice(&buf[22..38]);

    pending.set(Some((src_mac, src_ipv6)));
}

/// Build a Neighbor Solicitation Ethernet frame that appears to come from
/// `remote` asking "who has `our_ipv6`?".
///
/// When smoltcp processes this NS it:
/// 1. Records `{remote_ipv6 → remote_mac}` in the neighbor cache (from the
///    Source Link-Layer Address option).
/// 2. Replies with a Neighbor Advertisement to the remote host.
///
/// Layout (86 bytes total):
///
/// ```text
/// [0-5]   dst MAC  <our MAC>          (unicast — frame is "to us")
/// [6-11]  src MAC  <remote MAC>
/// [12-13] 0x86DD                      (IPv6)
/// [14-53] IPv6 hdr (src=remote, dst=us, NH=58, HL=255, len=32)
/// [54]    type=135 (NS)
/// [55]    code=0
/// [56-57] checksum
/// [58-61] reserved (0)
/// [62-77] target   <our IPv6>
/// [78]    opt type=1 (Source Link-Layer Address)
/// [79]    opt len=1  (8 bytes)
/// [80-85] MAC      <remote MAC>
/// ```
fn construct_synthetic_ns(
    frame: &mut [u8; NDP_FRAME_LEN],
    our_mac: &[u8; 6],
    our_ipv6: &[u8; 16],
    remote_mac: &[u8; 6],
    remote_ipv6: &[u8; 16],
) {
    frame[0..6].copy_from_slice(our_mac);
    frame[6..12].copy_from_slice(remote_mac);
    frame[12] = 0x86;
    frame[13] = 0xDD;

    frame[14] = 0x60; // version 6
    frame[15] = 0;
    frame[16] = 0;
    frame[17] = 0;
    frame[18] = 0;
    frame[19] = 32; // payload length
    frame[20] = 58; // next header: ICMPv6
    frame[21] = 255; // hop limit (RFC 4861 §4.3)
    frame[22..38].copy_from_slice(remote_ipv6);
    frame[38..54].copy_from_slice(our_ipv6);

    frame[54] = 135; // ICMPv6 type: Neighbor Solicitation
    frame[55] = 0; // code
    frame[56] = 0; // checksum (zeroed for calculation)
    frame[57] = 0;
    frame[58] = 0; // reserved
    frame[59] = 0;
    frame[60] = 0;
    frame[61] = 0;
    frame[62..78].copy_from_slice(our_ipv6); // target = our address

    frame[78] = 1; // SLLA option
    frame[79] = 1; // length = 1 × 8 bytes
    frame[80..86].copy_from_slice(remote_mac);

    let cksum = icmpv6_checksum_ndp(frame);
    frame[56] = (cksum >> 8) as u8;
    frame[57] = (cksum & 0xFF) as u8;
}

/// ICMPv6 checksum (RFC 4443 §2.3) for a Neighbor Solicitation / Neighbor
/// Advertisement carried in an [`NDP_FRAME_LEN`]-byte Ethernet frame.
///
/// Pseudo-header: src IPv6 (16) + dst IPv6 (16) + upper-layer length (4) +
/// next header (4). The caller must zero `buf[56..58]` first.
fn icmpv6_checksum_ndp(buf: &[u8; NDP_FRAME_LEN]) -> u16 {
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
    sum += 32_u32; // upper-layer length
    sum += 58_u32; // next header = ICMPv6
    i = 54;
    while i < NDP_FRAME_LEN {
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

    // -------------------------------------------------------------------
    // NeighborLearningDriver: pure-function tests
    // -------------------------------------------------------------------

    use core::cell::Cell;

    /// Build a minimal 60-byte unicast IPv6 Ethernet frame from a known peer
    /// to us. UDP payload (NH=17) is enough — the queueing logic only
    /// inspects the Ethernet + IPv6 header, not the upper layer.
    fn make_unicast_ipv6_frame(
        dst_mac: [u8; 6],
        src_mac: [u8; 6],
        src_ipv6: [u8; 16],
        dst_ipv6: [u8; 16],
    ) -> [u8; 60] {
        let mut f = [0u8; 60];
        f[0..6].copy_from_slice(&dst_mac);
        f[6..12].copy_from_slice(&src_mac);
        f[12] = 0x86;
        f[13] = 0xDD;
        f[14] = 0x60;
        f[19] = 6; // payload length = 6 (just enough header)
        f[20] = 17; // NH = UDP
        f[21] = 64; // hop limit
        f[22..38].copy_from_slice(&src_ipv6);
        f[38..54].copy_from_slice(&dst_ipv6);
        f
    }

    #[test]
    fn queue_neighbor_records_src_from_unicast_ipv6_frame() {
        let pending: Cell<Option<([u8; 6], [u8; 16])>> = Cell::new(None);
        let src_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let src_ipv6 = [
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        ];
        let our_mac = [0x9c, 0x13, 0x9e, 0xd7, 0xbd, 0xa8];
        let our_ipv6 = [
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x9e, 0x13, 0x9e, 0xff, 0xfe, 0xd7, 0xbd, 0xa8,
        ];
        let frame = make_unicast_ipv6_frame(our_mac, src_mac, src_ipv6, our_ipv6);

        super::queue_neighbor_from_frame(&frame, &pending);

        assert_eq!(pending.get(), Some((src_mac, src_ipv6)));
    }

    #[test]
    fn queue_neighbor_ignores_multicast_destination() {
        let pending: Cell<Option<([u8; 6], [u8; 16])>> = Cell::new(None);
        // Multicast MAC (low bit of first byte set)
        let dst_mac = [0x33, 0x33, 0x00, 0x00, 0x00, 0x01];
        let src_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let src_ipv6 = [
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        ];
        let frame = make_unicast_ipv6_frame(dst_mac, src_mac, src_ipv6, [0xff; 16]);

        super::queue_neighbor_from_frame(&frame, &pending);

        assert_eq!(pending.get(), None);
    }

    #[test]
    fn queue_neighbor_ignores_unspecified_source() {
        let pending: Cell<Option<([u8; 6], [u8; 16])>> = Cell::new(None);
        let our_mac = [0x9c, 0x13, 0x9e, 0xd7, 0xbd, 0xa8];
        let frame = make_unicast_ipv6_frame(
            our_mac,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0; 16], // src = ::
            [0xff; 16],
        );

        super::queue_neighbor_from_frame(&frame, &pending);

        assert_eq!(pending.get(), None);
    }

    #[test]
    fn queue_neighbor_does_not_overwrite_existing_entry() {
        let existing = (
            [1u8, 2, 3, 4, 5, 6],
            [
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
            ],
        );
        let pending: Cell<Option<([u8; 6], [u8; 16])>> = Cell::new(Some(existing));
        let our_mac = [0x9c, 0x13, 0x9e, 0xd7, 0xbd, 0xa8];
        let frame = make_unicast_ipv6_frame(
            our_mac,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
            ],
            [0xff; 16],
        );

        super::queue_neighbor_from_frame(&frame, &pending);

        assert_eq!(pending.get(), Some(existing));
    }

    #[test]
    fn queue_neighbor_ignores_non_ipv6_frame() {
        let pending: Cell<Option<([u8; 6], [u8; 16])>> = Cell::new(None);
        let mut frame = [0u8; 60];
        frame[12] = 0x08; // IPv4 EtherType
        frame[13] = 0x00;

        super::queue_neighbor_from_frame(&frame, &pending);

        assert_eq!(pending.get(), None);
    }

    #[test]
    fn synthetic_ns_has_expected_layout() {
        let our_mac = [0x9c, 0x13, 0x9e, 0xd7, 0xbd, 0xa8];
        let our_ipv6 = [
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x9e, 0x13, 0x9e, 0xff, 0xfe, 0xd7, 0xbd, 0xa8,
        ];
        let remote_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let remote_ipv6 = [
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        ];
        let mut frame = [0u8; super::NDP_FRAME_LEN];

        super::construct_synthetic_ns(&mut frame, &our_mac, &our_ipv6, &remote_mac, &remote_ipv6);

        // Ethernet
        assert_eq!(frame[0..6], our_mac); // dst MAC = us (frame is to us)
        assert_eq!(frame[6..12], remote_mac); // src MAC = peer
        assert_eq!(frame[12..14], [0x86, 0xDD]);
        // IPv6
        assert_eq!(frame[14] & 0xF0, 0x60); // version = 6
        assert_eq!(u16::from_be_bytes([frame[18], frame[19]]), 32); // payload len
        assert_eq!(frame[20], 58); // NH = ICMPv6
        assert_eq!(frame[21], 255); // hop limit
        assert_eq!(frame[22..38], remote_ipv6); // src = peer
        assert_eq!(frame[38..54], our_ipv6); // dst = us
        // ICMPv6 NS
        assert_eq!(frame[54], 135); // NS
        assert_eq!(frame[55], 0);
        assert_eq!(frame[58..62], [0, 0, 0, 0]); // reserved
        assert_eq!(frame[62..78], our_ipv6); // target = us
        // SLLA option
        assert_eq!(frame[78], 1); // option type
        assert_eq!(frame[79], 1); // option length
        assert_eq!(frame[80..86], remote_mac);
    }

    #[test]
    fn synthetic_ns_checksum_validates() {
        let our_mac = [0x9c, 0x13, 0x9e, 0xd7, 0xbd, 0xa8];
        let our_ipv6 = [
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x9e, 0x13, 0x9e, 0xff, 0xfe, 0xd7, 0xbd, 0xa8,
        ];
        let remote_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let remote_ipv6 = [
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        ];
        let mut frame = [0u8; super::NDP_FRAME_LEN];
        super::construct_synthetic_ns(&mut frame, &our_mac, &our_ipv6, &remote_mac, &remote_ipv6);

        let written = u16::from_be_bytes([frame[56], frame[57]]);
        // Recompute over the post-conversion frame with the checksum field zeroed.
        let mut verify = frame;
        verify[56] = 0;
        verify[57] = 0;
        let recomputed = super::icmpv6_checksum_ndp(&verify);

        assert_eq!(written, recomputed);
        assert_ne!(written, 0);
    }
}
