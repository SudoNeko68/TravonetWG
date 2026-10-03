# TravonetWG 

[![Go Version](https://img.shields.io/badge/Go-1.22%2B-blue.svg)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![WireGuard Compatible](https://img.shields.io/badge/WireGuard-100%25%20Server%20Compatible-brightgreen.svg)](https://www.wireguard.com)

**TravonetWG** is an advanced in-client L3 evasion fork of [`wireguard-go`](https://git.zx2c4.com/wireguard-go). It bypasses deep packet inspection (TSPU / DPI) in restrictive network environments without requiring any server-side changes, special patches, or non-standard protocols.
---

##  How It Works: The Proven Evasion Pipeline

During a standard WireGuard connection, the client sends a distinct 148-byte UDP packet (`0x01` handshake initiation). TSPU boxes detect the 148-byte length on UDP ports and block the flow.

TravonetWG intercepts handshake initiation packets at the raw socket level and executes an evasion pipeline:

```
[Client] ──(1) junk UDP datagram (64B)─────────────────────────────► [DPI] (confused flow)
         ──(2) fake UDP handshake (148B, TTL=10..11)───────────────► [TSPU / DPI] (state poisoned) ───X (dies before server)
         ──(3) Frag #1 (offset=0, len=8, MF=1, TTL=64)────────────► [TSPU / DPI] ───► [WireGuard Server]
         ──(4) Frag #2 (offset=8, len=148, MF=0, TTL=64)──────────► [TSPU / DPI] ───► [WireGuard Server]
```

1. **Pre-Junk (`junk(64)`):** A small random UDP datagram precedes the handshake, disrupting DPI protocol-matching heuristics.
2. **Fake UDP (`fake_udp(148, ttl=auto)`):** A complete 148-byte UDP datagram with `0x01` initiation byte sent with a low TTL (calculated by Auto-TTL). It reaches the ISP's TSPU box (hops 8–11), registers inside the DPI's state table, and expires in transit before reaching the destination server.
3. **Transport Split Fragmentation (`frag(8)` + `frag(148)`):**
   - Fragment 1 contains **only** the 8-byte UDP header (no WireGuard data).
   - Fragment 2 contains the 148-byte WireGuard payload without UDP ports.
   - Intermediate routers and NAT reassemble standard RFC 791 fragments cleanly, and the standard WireGuard server receives the full, legitimate Handshake Initiation packet.

---

##  Dual Configuration Modes

TravonetWG provides two distinct modes depending on your preference:

### Mode 1: Embedded Evasion Settings in `.conf`
Add evasion directives directly inside the `[Interface]` section of your WireGuard configuration:

```ini
[Interface]
PrivateKey = <your_private_key>
Address = 172.16.0.2/32
DNS = 1.1.1.1
MTU = 1280

# Evasion directives:
FakeTTL = auto
PreJunk = 64
Strategy = junk(64) -> fake_udp(148) -> frag(8) -> frag(148)

[Peer]
PublicKey = <server_public_key>
Endpoint = 8.34.70.70:500
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

Launch with:
```bash
sudo ./travonet-wg -f -c warp.conf warp
```

---

### Mode 2: Vanilla WireGuard `.conf` + CLI Flags (or Zero-Config)
Use a **100% standard, unpatched WireGuard `.conf` file** (e.g., exported directly from Cloudflare WARP, Mullvad, ProtonVPN, or standard `wg-quick`):

```ini
[Interface]
PrivateKey = <your_private_key>
Address = 172.16.0.2/32
DNS = 1.1.1.1
MTU = 1280

[Peer]
PublicKey = <server_public_key>
Endpoint = 8.34.70.70:500
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

#### Option A: Zero-Config (Intelligent Auto-Detection)
Pass no evasion flags. TravonetWG will automatically probe the hop distance to the endpoint, configure Auto-TTL, and run the proven default evasion pipeline:
```bash
sudo ./travonet-wg -f -c clean-warp.conf warp
```

#### Option B: CLI Parameter Overrides
Override parameters on the command line (CLI flags always take highest precedence):
```bash
# Auto-measure TTL:
sudo ./travonet-wg -f -c clean-warp.conf --fake-ttl auto warp

# Specific custom TTL:
sudo ./travonet-wg -f -c clean-warp.conf --fake-ttl 10 warp

# Custom evasion pipeline:
sudo ./travonet-wg -f -c clean-warp.conf -s "junk(64) -> fake_udp(148) -> frag(8) -> frag(148)" warp

# Disable evasion completely (run as standard wireguard-go):
sudo ./travonet-wg -f -c clean-warp.conf --no-evasion warp
```

---

##  Auto-TTL Hop Distance Probe

Because TSPU DPI hardware is located within domestic transit/backbone networks (typically hops 8–11 in Russia), fake packets must have a TTL large enough to traverse TSPU, but small enough to expire before reaching the foreign server.

TravonetWG includes a built-in traceroute engine (`conn.MeasureTargetTTL`) that:
- Probes the network path to the endpoint in ~1 second using non-invasive UDP/ICMP bursts.
- Determines total hop count (e.g. 15 hops to Cloudflare Stockholm).
- Computes optimal `FakeTTL = totalHops - 4` (constrained within the Russian DPI bypass window: 8–11).

---

##  Strategy DSL Syntax

TravonetWG features a domain-specific language (DSL) to customize packet sequences:

| Action | Description | Example |
| :--- | :--- | :--- |
| `junk(size, [badsum])` | Sends a random UDP packet | `junk(64)`, `junk(size=128, badsum=true)` |
| `fake_udp(size, [ttl])` | Full UDP datagram with `0x01` initiation header | `fake_udp(148)`, `fake_udp(size=148, ttl=10)` |
| `frag(offset, len, [mf, ttl])` | Legitimate IP fragment of the handshake | `frag(8)`, `frag(offset=0, len=8, mf=true)` |
| `fake_frag(offset, len, [mf, ttl])` | Injected fake fragment | `fake_frag(offset=88, len=32, mf=0, ttl=10)` |
| `sleep(duration)` | Timing delay between packets | `sleep(10ms)` |

---

##  Building & Running

### Prerequisites
- Linux with Go 1.22+ installed
- Root permissions (required for raw sockets and TUN interface creation)

### Build
```bash
git clone https://github.com/SudoNeko68/TravonetWG.git
cd TravonetWG
go build -o travonet-wg .
```

### Full System VPN Launcher (`run_warp.sh`)
To route all system internet traffic and DNS through Cloudflare WARP using TravonetWG:
```bash
# Mode 1 (embedded config):
sudo ./run_warp.sh warp.conf

# Mode 2 (vanilla config + auto evasion):
sudo ./run_warp.sh clean-warp.conf

# Mode 2 with CLI override:
sudo ./run_warp.sh clean-warp.conf --fake-ttl 10
```

Verify your connection:
```bash
curl https://cloudflare.com/cdn-cgi/trace
# Expected: warp=on, loc=RU, colo=ARN
```

---

## License
MIT License. Copyright (C) 2017-2025 WireGuard LLC. Copyright (C) 2026 Travonet.
