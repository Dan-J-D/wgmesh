# 🔗 wgmesh
> Secure, peer-to-peer, decentralized mesh networking using WireGuard and libp2p.

<p align="center">
  <img src="https://github.com/Dan-J-D/wgmesh/blob/main/assets/banner.png?raw=true" alt="Centered Image" width="420"/>
</p>

## ✨ Overview
**wgmesh** is a lightweight tool that transforms a collection of nodes into a **distributed, encrypted, and decentralized mesh network.** It combines [WireGuard](https://www.wireguard.com/)'s fast, secure VPN tunneling with [libp2p](https://libp2p.io/)'s powerful peer-to-peer networking to form a resilient overlay mesh -- no central server required.

Perfect for:
- 🌍 Distributed VPN mesh networks
- 📦 Private infrastructure overlays
- 🛰 Remote clusters or sensor networks

## 🚀 Quick Start
### 1. Install Go
Make sure you have Go 1.23.8+ installed:
https://golang.org/dl/

### 2. Clone and Build
```bash
git clone https://github.com/dan-j-d/wgmesh.git
cd wgmesh
go build
```

### 3. Run It
```bash
sudo ./wgmesh \
  --public-ip <YOUR_PUBLIC_IP> \
  --wireguard-ip 10.0.0.1 \
  --port 37950 \
  --wireguard-port 51820 \
  --wireguard-interface wg0
 ```
ℹ️ On first run, the tool will generate and store its iconfig under ./data/.

## 🔌 Connecting Peers
To connect to another peer:
1. Ask the other node to run /connect-string to get its connection JSON.
2. Run the following command on your node:
```bash
/connect [{"Addr":"/ip4/1.2.3.4/tcp/37950/p2p/QmPeerID"}, ...]
```
3. The nodes will automatically establish secure connections and form a mesh.

## 💻 CLI Commands
| Command         | Description                                 |
|-----------------|---------------------------------------------|
| /connect        | Connects to a peer using its multiaddr(s)   |
| /connect-string | Outputs connection JSON strings for sharing |
| /peers          | Lists currently connected libp2p peers      |
| /exit           | Gracefully shuts down the node              |

## 📁 Data & Configs
All persistent state (keys, WireGuard configs, DHT store) are stored under the specified `--data-path`. On startup, the tool will reuse previous identities and settings if present.

## 🔐 Security
- Uses **WireGuard’s modern encryption** for tunnel traffic.
- Peer communication secured via **libp2p’s TLS and optional shared secrets.**
- Can run on public internet or in private networks.
- Optionally supports a shared secret (`--pre-shared-key`) to restrict network access.

## 🧪 Example Use Case: Private VPN Mesh
Run this on multiple VPS instances, assign each a unique `--wireguard-ip`, and they will:
- Discover each other
- Exchange encrypted configs
- Form a decentralized VPN mesh with no central coordinator

## 🛠 Requirements
- `Wireguard` (Kernel module and tools required)
- `Go` 1.23.8+
- Supported platforms: Linux and Windows

## 🧑‍💻 License
Apache 2.0 License. Feel free to fork, contribute, or use this in your own systems.
