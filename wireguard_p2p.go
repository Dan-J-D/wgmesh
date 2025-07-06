/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-playground/validator/v10"
	leveldb "github.com/ipfs/go-ds-leveldb"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/pnet"
	"github.com/libp2p/go-libp2p/p2p/host/peerstore/pstoreds"
	"github.com/libp2p/go-libp2p/p2p/muxer/yamux"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	ma "github.com/multiformats/go-multiaddr"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const PeerUpdateTopic = "peers"

type slogWriter struct {
	level slog.Level
}

func (sw slogWriter) Write(p []byte) (n int, err error) {
	msg := strings.TrimSpace(string(p))
	if msg != "" {
		slog.Log(context.Background(), sw.level, msg)
	}
	return len(p), nil
}

type wireguardPeerConfig struct {
	PublicKey    string
	InterfaceIP  net.IP
	EndpointIP   net.IP
	EndpointPort uint16
	PreSharedKey string
}

type wireguardConfig struct {
	Interface  string
	PrivateKey string
	Address    net.IP
	ListenPort uint16
	Peers      map[string]wireguardPeerConfig
}

func (wc *wireguardConfig) String() string {
	str := "[Interface]\n"
	str += "PrivateKey = " + wc.PrivateKey + "\n"
	str += "Address = " + wc.Address.String() + "/32\n"
	str += "ListenPort = " + fmt.Sprintf("%d\n", wc.ListenPort)
	str += "\n"

	for _, peer := range wc.Peers {
		str += "[Peer]\n"
		str += "PublicKey = " + peer.PublicKey + "\n"
		str += "Endpoint = " + peer.EndpointIP.String() + ":" + strconv.FormatUint(uint64(peer.EndpointPort), 10) + "\n"
		str += "AllowedIPs = " + peer.InterfaceIP.String() + "/32\n"
		str += "PresharedKey = " + peer.PreSharedKey + "\n"
		str += "\n"
	}
	return str
}

type wireguardNetworkNotifiee struct {
	wg *WireguardP2P
}

func (wgn *wireguardNetworkNotifiee) Listen(network network.Network, multiAddr ma.Multiaddr) {
	slog.Info("Listen started", "multiaddr", multiAddr)
}

func (wgn *wireguardNetworkNotifiee) ListenClose(network network.Network, multiAddr ma.Multiaddr) {
	slog.Info("Listen closed", "multiaddr", multiAddr)
}

func (wgn *wireguardNetworkNotifiee) Connected(net network.Network, con network.Conn) {
	slog.Info("Connected to peer", "peer_id", con.RemotePeer(), "remote_addr", con.RemoteMultiaddr())

	for _, addr := range wgn.wg.GetHost().Peerstore().PeersWithAddrs() {
		if addr == wgn.wg.host.ID() {
			continue // skip self
		}

		addrInfo := wgn.wg.host.Peerstore().PeerInfo(addr)
		if len(addrInfo.Addrs) > 0 {
			// make sure the peer is saved permanently
			wgn.wg.host.Peerstore().AddAddrs(addr, addrInfo.Addrs, peerstore.PermanentAddrTTL)
		}
	}
}

func (wgn *wireguardNetworkNotifiee) Disconnected(network network.Network, con network.Conn) {
	slog.Info("Disconnected from peer", "peer_id", con.RemotePeer())
}

type Config struct {
	DataPath string `validate:"required"`

	PublicIp           string `validate:"required,ip"`
	Port               int    `validate:"required,min=1,max=65535"`
	WireguardIp        string `validate:"required,ip"`
	WireguardPort      int    `validate:"required,min=1,max=65535"`
	WireguardInterface string `validate:"required"`

	PreSharedKey           string // optional
	WireguardPrivateKey    string // optional
	PeerIdentityPrivateKey string // optional
}

type WireguardP2P struct {
	config          Config
	publicIpAddress net.IP

	peerPrivateKey crypto.PrivKey
	host           host.Host
	dht            *dht.IpfsDHT
	pubsub         *pubsub.PubSub
	peersTopic     *pubsub.Topic
	peerSub        *pubsub.Subscription

	wgPsk         wgtypes.Key
	wgConfig      wireguardConfig
	wgConfigMutex sync.RWMutex
	wgPrivateKey  wgtypes.Key

	backgroundCtx    context.Context
	backgroundCancel context.CancelFunc
}

func validateConfig(cfg *Config) error {
	v := validator.New()
	return v.Struct(cfg)
}

func NewWireguardP2P(config Config) (*WireguardP2P, error) {
	if err := validateConfig(&config); err != nil {
		slog.Error("Invalid configuration", "error", err)
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	wg := new(WireguardP2P)
	wg.config = config

	wg.publicIpAddress = net.ParseIP(config.PublicIp)
	if wg.publicIpAddress == nil {
		slog.Error("Invalid public IP address", "public_ip", config.PublicIp)
		return nil, fmt.Errorf("invalid public IP address: %s", config.PublicIp)
	}

	var err error
	if len(config.WireguardPrivateKey) == 0 {
		wg.wgPrivateKey, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			slog.Error("Failed to generate WireGuard private key", "error", err)
			return nil, fmt.Errorf("failed to generate private key: %w", err)
		}
		wg.config.WireguardPrivateKey = wg.wgPrivateKey.String() // already base64 encoded
	} else {
		wg.wgPrivateKey, err = wgtypes.ParseKey(string(config.WireguardPrivateKey))
		if err != nil {
			slog.Error("Failed to parse WireGuard private key", "error", err)
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
	}

	if len(config.PeerIdentityPrivateKey) == 0 {
		wg.peerPrivateKey, _, err = crypto.GenerateKeyPair(crypto.Ed25519, 0)
		if err != nil {
			slog.Error("Failed to generate peer identity private key", "error", err)
			return nil, fmt.Errorf("failed to generate peer identity private key: %w", err)
		}
		privKey, err := crypto.MarshalPrivateKey(wg.peerPrivateKey)
		if err != nil {
			slog.Error("Failed to marshal peer identity private key", "error", err)
			return nil, fmt.Errorf("failed to marshal peer identity private key: %w", err)
		}
		wg.config.PeerIdentityPrivateKey = base64.StdEncoding.EncodeToString(privKey)
	} else {
		privKey, err := base64.StdEncoding.DecodeString(config.PeerIdentityPrivateKey)
		if err != nil {
			slog.Error("Failed to decode peer identity private key", "error", err)
			return nil, fmt.Errorf("failed to decode peer identity private key: %w", err)
		}

		wg.peerPrivateKey, err = crypto.UnmarshalPrivateKey(privKey)
		if err != nil {
			slog.Error("Failed to unmarshal peer identity private key", "error", err)
			return nil, fmt.Errorf("failed to unmarshal peer identity private key: %w", err)
		}
	}

	wg.backgroundCtx, wg.backgroundCancel = context.WithCancel(context.Background())

	psk := sha256.New()
	_, err = psk.Write([]byte(wg.config.PreSharedKey))
	if err != nil {
		wg.backgroundCancel()
		slog.Error("Failed to write pre-shared key", "error", err)
		return nil, fmt.Errorf("failed to write pre-shared key: %w", err)
	}
	psk.Write([]byte{0x5d, 0xa5, 0x86, 0xed, 0xc7, 0x30, 0x5a, 0xb7, 0x2c, 0x0d, 0x4c, 0x3d, 0xff, 0x67, 0x51, 0xe5}) // Random pre-shared salt (generated from `openssl rand -hex 16`)

	peerStoreDb, err := leveldb.NewDatastore(path.Join(wg.config.DataPath, "peerstore"), nil)
	if err != nil {
		wg.backgroundCancel()
		slog.Error("Failed to create peerstore datastore", "error", err)
		return nil, fmt.Errorf("failed to create peerstore datastore: %w", err)
	}

	peerStore, err := pstoreds.NewPeerstore(wg.backgroundCtx, peerStoreDb, pstoreds.DefaultOpts())
	if err != nil {
		wg.backgroundCancel()
		peerStoreDb.Close()
		slog.Error("Failed to create peerstore", "error", err)
		return nil, fmt.Errorf("failed to create peerstore: %w", err)
	}

	wg.host, err = libp2p.New(
		libp2p.UserAgent("libp2p-test/1.0.0"),
		libp2p.Identity(wg.peerPrivateKey),
		libp2p.EnableAutoNATv2(),
		libp2p.EnableHolePunching(),
		libp2p.EnableRelay(),
		libp2p.PrivateNetwork(pnet.PSK(psk.Sum(pnet.PSK{}))),
		libp2p.Security(libp2ptls.ID, libp2ptls.New),
		libp2p.Muxer(yamux.ID, yamux.DefaultTransport),
		libp2p.Peerstore(peerStore),
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", wg.config.Port), fmt.Sprintf("/ip6/::/tcp/%d", wg.config.Port)))
	if err != nil {
		wg.backgroundCancel()
		peerStore.Close()
		slog.Error("Failed to create libp2p host", "error", err)
		return nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}
	slog.Info("Libp2p host created", "peer_id", wg.host.ID(), "addresses", wg.host.Addrs())

	wg.host.Network().Notify(&wireguardNetworkNotifiee{wg: wg})

	psk.Write([]byte("wireguard_p2p"))
	wg.wgPsk, err = wgtypes.NewKey(psk.Sum(nil))
	if err != nil {
		wg.backgroundCancel()
		wg.host.Close()
		slog.Error("Failed to create WireGuard pre-shared key", "error", err)
		return nil, fmt.Errorf("failed to create WireGuard pre-shared key: %w", err)
	}

	dhtDataStore, err := leveldb.NewDatastore(path.Join(wg.config.DataPath, "dht"), nil)
	if err != nil {
		wg.backgroundCancel()
		wg.host.Close()
		slog.Error("Failed to create DHT datastore", "error", err)
		return nil, fmt.Errorf("failed to create DHT datastore: %w", err)
	}
	wg.dht, err = dht.New(wg.backgroundCtx, wg.host,
		dht.Mode(dht.ModeAutoServer),
		dht.Datastore(dhtDataStore),
		dht.ProtocolPrefix("/dht"))
	if err != nil {
		wg.backgroundCancel()
		wg.host.Close()
		dhtDataStore.Close()
		slog.Error("Failed to create DHT", "error", err)
		return nil, fmt.Errorf("failed to create DHT: %w", err)
	}
	slog.Info("DHT created", "peer_id", wg.dht.Host().ID(), "addresses", wg.dht.Host().Addrs())

	wg.pubsub, err = pubsub.NewGossipSub(wg.backgroundCtx, wg.host)
	if err != nil {
		wg.backgroundCancel()
		wg.dht.Close()
		wg.host.Close()
		slog.Error("Failed to create PubSub", "error", err)
		return nil, fmt.Errorf("failed to create PubSub: %w", err)
	}
	slog.Info("PubSub created")

	wg.peersTopic, err = wg.pubsub.Join(PeerUpdateTopic)
	if err != nil {
		wg.backgroundCancel()
		wg.dht.Close()
		wg.host.Close()
		slog.Error("Failed to join PubSub topic", "topic", PeerUpdateTopic, "error", err)
		return nil, fmt.Errorf("failed to join PubSub topic %s: %w", PeerUpdateTopic, err)
	}
	slog.Info("Joined PubSub topic", "topic", PeerUpdateTopic)

	wg.peerSub, err = wg.peersTopic.Subscribe()
	if err != nil {
		wg.backgroundCancel()
		wg.peersTopic.Close()
		wg.dht.Close()
		wg.host.Close()
		slog.Error("Failed to subscribe to PubSub topic", "topic", PeerUpdateTopic, "error", err)
		return nil, fmt.Errorf("failed to subscribe to PubSub topic %s: %w", PeerUpdateTopic, err)
	}
	slog.Info("Subscribed to PubSub topic", "topic", PeerUpdateTopic)

	wg.wgConfig = wireguardConfig{
		Interface:  wg.config.WireguardInterface,
		PrivateKey: wg.config.WireguardPrivateKey,
		Address:    net.ParseIP(wg.config.WireguardIp),
		ListenPort: uint16(wg.config.WireguardPort),
		Peers:      make(map[string]wireguardPeerConfig, 0),
	}

	err = writeWireGuardInterface(wg.config.DataPath, wg.wgConfig)
	if err != nil {
		wg.backgroundCancel()
		wg.peersTopic.Close()
		wg.dht.Close()
		wg.host.Close()
		slog.Error("Failed to write WireGuard interface config", "error", err)
		return nil, fmt.Errorf("failed to write WireGuard interface config: %w", err)
	}
	slog.Info("WireGuard interface config written", "interface", wg.config.WireguardInterface)

	slog.Info("WireGuard P2P instance created", "interface", wg.config.WireguardInterface, "peer_id", wg.host.ID(), "addresses", wg.host.Addrs())

	return wg, nil
}

func (wg *WireguardP2P) GetConfig() *Config {
	config := new(Config)
	*config = wg.config

	return config
}

func (wg *WireguardP2P) GetHost() host.Host {
	return wg.host
}

func (wg *WireguardP2P) GetDHT() *dht.IpfsDHT {
	return wg.dht
}

func (wg *WireguardP2P) GetPubSub() *pubsub.PubSub {
	return wg.pubsub
}

func (wg *WireguardP2P) GetPeerId() peer.ID {
	if wg.host == nil {
		return ""
	}
	return wg.host.ID()
}

func (wg *WireguardP2P) GetAddrs() []string {
	if wg.host == nil {
		return nil
	}

	publicIp := fmt.Sprintf("/ip4/%s/tcp/%d", wg.publicIpAddress.String(), wg.config.Port)
	hasPublicIp := false

	addrs := make([]string, 0, len(wg.host.Addrs()))
	for _, addr := range wg.host.Addrs() {
		addrs = append(addrs, addr.String()+"/p2p/"+wg.host.ID().String())

		if strings.HasPrefix(addr.String(), publicIp) {
			hasPublicIp = true
		}
	}

	if !hasPublicIp {
		publicAddr, err := ma.NewMultiaddr(publicIp + "/p2p/" + wg.host.ID().String())
		if err != nil {
			fmt.Printf("Error creating public address: %v\n", err)
		}
		addrs = append(addrs, publicAddr.String())
	}

	return addrs
}

func (wg *WireguardP2P) Start() error {
	err := installWireguardInterface(wg.config.WireguardInterface, wg.config.DataPath)
	if err != nil {
		slog.Error("Failed to install WireGuard interface", "error", err)
		return fmt.Errorf("failed to install WireGuard interface: %w", err)
	}
	slog.Info("WireGuard interface installed", "interface", wg.config.WireguardInterface)

	// Kad-DHT Bootstrap
	go func() {
		slog.Info("Bootstrapping DHT")
		if err := wg.dht.Bootstrap(wg.backgroundCtx); err != nil {
			if err == context.Canceled {
				return // Context canceled, exit gracefully
			}

			slog.Error("Error bootstrapping DHT", "error", err)
			fmt.Printf("Error bootstrapping DHT: %v\n", err)
			return
		}
	}()

	// Receive WireGuard peer updates
	go func() {
		for {
			msg, err := wg.peerSub.Next(wg.backgroundCtx)
			if err != nil {
				if err == context.Canceled {
					return
				}

				slog.Error("Error receiving message from PubSub", "error", err)
				fmt.Printf("Error receiving message: %v\n", err)
				continue
			}

			if msg == nil {
				slog.Warn("Received nil message from PubSub, skipping")
				fmt.Println("Received nil message, skipping")
				continue
			}

			if msg.GetFrom() == wg.host.ID() {
				continue // skip messages from self
			}

			wgPeerData := strings.Split(string(msg.Data), "@")
			if len(wgPeerData) != 3 {
				slog.Error("Invalid WireGuard peer data format", "data", string(msg.Data))
				continue
			}

			udpAddr := strings.Split(wgPeerData[0], ":")
			if len(udpAddr) != 2 {
				slog.Error("Invalid WireGuard peer endpoint format", "endpoint", wgPeerData[0])
				continue
			}

			peerEndpointIP := net.ParseIP(udpAddr[0])
			if peerEndpointIP == nil {
				slog.Error("Invalid IP address in WireGuard peer endpoint", "ip", udpAddr[0])
				continue
			}

			peerEndpointPort, err := strconv.Atoi(udpAddr[1])
			if err != nil || peerEndpointPort <= 0 || peerEndpointPort > 65535 {
				slog.Error("Invalid port number in WireGuard peer endpoint", "port", udpAddr[1])
				continue
			}

			peerInterfaceIp := net.ParseIP(wgPeerData[1])
			if peerInterfaceIp == nil {
				slog.Error("Invalid interface IP address in WireGuard peer data", "interface_ip", wgPeerData[1])
				continue
			}

			wg.wgConfigMutex.Lock()
			if peer, ok := wg.wgConfig.Peers[msg.GetFrom().String()]; ok {
				if peer.EndpointIP.Equal(peerEndpointIP) && peer.EndpointPort == uint16(peerEndpointPort) && peer.InterfaceIP.Equal(peerInterfaceIp) && peer.PublicKey == wgPeerData[2] {
					wg.wgConfigMutex.Unlock()
					continue
				}
			}

			wg.wgConfig.Peers[msg.GetFrom().String()] = wireguardPeerConfig{
				EndpointIP:   peerEndpointIP,
				EndpointPort: uint16(peerEndpointPort),
				InterfaceIP:  peerInterfaceIp,
				PublicKey:    wgPeerData[2],
				PreSharedKey: wg.wgPsk.String(),
			}

			wg.wgConfigMutex.Unlock()

			err = writeWireGuardInterface(wg.config.DataPath, wg.wgConfig)
			if err != nil {
				slog.Error("Failed to write WireGuard interface config", "error", err)
				continue
			}
			slog.Info("WireGuard interface config updated", "interface", wg.config.WireguardInterface, "peer_id", msg.GetFrom())

			err = syncWireguardInterface(wg.config.WireguardInterface, wg.config.DataPath)
			if err != nil {
				slog.Error("Failed to sync WireGuard interface", "error", err)
				continue
			}
			slog.Info("WireGuard interface synced", "interface", wg.config.WireguardInterface, "peer_id", msg.GetFrom())
		}
	}()

	// Auto reconnect & broadcast wireguard peer data
	go func() {
		for {
			if len(wg.host.Network().Peers()) == 0 {
				for _, peer := range wg.host.Peerstore().PeersWithAddrs() {
					if peer == wg.host.ID() {
						continue // Skip self
					}

					addrInfo := wg.host.Peerstore().PeerInfo(peer)
					ctx, cancel := context.WithTimeout(wg.backgroundCtx, 3*time.Second)
					err := wg.host.Connect(ctx, addrInfo)
					cancel()
					if err != nil {
						if err == context.Canceled {
							return // Context canceled, exit gracefully
						}

						slog.Error("Error connecting to peer", "peer_id", peer, "error", err)
						continue
					}

					slog.Info("Connected to peer", "peer_id", peer, "addresses", addrInfo.Addrs)
					break
				}
			}

			err := wg.peersTopic.Publish(wg.backgroundCtx, []byte(string(wg.publicIpAddress.String())+":"+strconv.FormatUint(uint64(wg.config.WireguardPort), 10)+"@"+wg.config.WireguardIp+"@"+wg.wgPrivateKey.PublicKey().String()))
			if err != nil {
				if err == context.Canceled {
					return // Context canceled, exit gracefully
				}

				slog.Error("Error publishing WireGuard peer data", "error", err)
				continue
			}

			time.Sleep(1 * time.Minute)
		}
	}()

	slog.Info("WireGuard P2P started", "interface", wg.config.WireguardInterface, "peer_id", wg.host.ID(), "addresses", wg.host.Addrs())

	return nil
}

func (wg *WireguardP2P) Close() error {
	wg.backgroundCancel()
	wg.peersTopic.Close()
	wg.dht.Close()
	wg.host.Close()

	if err := wg.dht.Close(); err != nil {
		slog.Error("Failed to close DHT", "error", err)
		return fmt.Errorf("failed to close DHT: %w", err)
	}

	if err := wg.host.Close(); err != nil {
		slog.Error("Failed to close host", "error", err)
		return fmt.Errorf("failed to close host: %w", err)
	}

	err := uninstallWireguardInterface(wg.config.WireguardInterface)
	if err != nil {
		slog.Error("Failed to uninstall WireGuard interface", "error", err)
		return fmt.Errorf("failed to uninstall wireguard interface: %v", err)
	}

	err = deleteWireGuardInterface(wg.config.WireguardInterface, wg.config.DataPath)
	if err != nil {
		slog.Error("Failed to delete WireGuard config file", "error", err)
		return fmt.Errorf("failed to delete wireguard config file: %v", err)
	}
	slog.Info("WireGuard interface deleted", "interface", wg.config.WireguardInterface)

	slog.Info("WireGuard P2P closed", "interface", wg.config.WireguardInterface, "peer_id", wg.host.ID())

	return nil
}
