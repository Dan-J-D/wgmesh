package main

import (
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"runtime"
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
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/pnet"
	"github.com/libp2p/go-libp2p/p2p/host/peerstore/pstoreds"
	"github.com/libp2p/go-libp2p/p2p/muxer/yamux"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const PeerUpdateTopic = "peers"

type wgPeer struct {
	PublicIp    net.IP
	InterfaceIP net.IP
	PublicKey   string
}

type Config struct {
	DhtDataPath   string `validate:"required"`
	PeerstorePath string `validate:"required"`

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

	wgPsk        wgtypes.Key
	wgClient     *wgctrl.Client
	wgPeers      map[string]wgPeer
	wgPeersMutex sync.RWMutex
	wgPrivateKey wgtypes.Key

	backgroundCtx    context.Context
	backgroundCancel context.CancelFunc
}

func validateConfig(cfg *Config) error {
	v := validator.New()
	return v.Struct(cfg)
}

func NewWireguardP2P(config Config) (*WireguardP2P, error) {
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	wg := new(WireguardP2P)
	wg.config = config
	wg.wgPeers = make(map[string]wgPeer)

	wg.publicIpAddress = net.ParseIP(config.PublicIp)
	if wg.publicIpAddress == nil {
		return nil, fmt.Errorf("invalid public IP address: %s", config.PublicIp)
	}

	var err error
	if len(config.WireguardPrivateKey) == 0 {
		wg.wgPrivateKey, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			return nil, fmt.Errorf("failed to generate private key: %w", err)
		}
		wg.config.WireguardPrivateKey = wg.wgPrivateKey.String() // already base64 encoded
	} else {
		wg.wgPrivateKey, err = wgtypes.ParseKey(string(config.WireguardPrivateKey))
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
	}

	if len(config.PeerIdentityPrivateKey) == 0 {
		wg.peerPrivateKey, _, err = crypto.GenerateKeyPairWithReader(crypto.Ed25519, -1, crand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate peer identity private key: %w", err)
		}
		privKey, err := crypto.MarshalPrivateKey(wg.peerPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal peer identity private key: %w", err)
		}
		wg.config.PeerIdentityPrivateKey = base64.StdEncoding.EncodeToString(privKey)
	} else {
		privKey, err := base64.StdEncoding.DecodeString(config.PeerIdentityPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decode peer identity private key: %w", err)
		}

		wg.peerPrivateKey, err = crypto.UnmarshalPrivateKey(privKey)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal peer identity private key: %w", err)
		}
	}

	wg.backgroundCtx, wg.backgroundCancel = context.WithCancel(context.Background())

	psk := sha256.New()
	_, err = psk.Write([]byte(wg.config.PreSharedKey))
	psk.Write([]byte{0x5d, 0xa5, 0x86, 0xed, 0xc7, 0x30, 0x5a, 0xb7, 0x2c, 0x0d, 0x4c, 0x3d, 0xff, 0x67, 0x51, 0xe5}) // Random pre-shared salt (generated from `openssl rand -hex 16`)

	peerStoreDb, err := leveldb.NewDatastore(wg.config.PeerstorePath, nil)
	if err != nil {
		wg.backgroundCancel()
		return nil, fmt.Errorf("failed to create peerstore datastore: %w", err)
	}

	peerStore, err := pstoreds.NewPeerstore(wg.backgroundCtx, peerStoreDb, pstoreds.DefaultOpts())
	if err != nil {
		wg.backgroundCancel()
		peerStoreDb.Close()
		return nil, fmt.Errorf("failed to create peerstore: %w", err)
	}

	wg.host, err = libp2p.New(
		libp2p.UserAgent("libp2p-test/1.0.0"),
		libp2p.Identity(wg.peerPrivateKey),
		libp2p.EnableAutoNATv2(),
		libp2p.EnableHolePunching(),
		libp2p.EnableRelay(),
		libp2p.PrivateNetwork(pnet.PSK(psk.Sum(nil))),
		libp2p.Security(libp2ptls.ID, libp2ptls.New),
		libp2p.Muxer(yamux.ID, yamux.DefaultTransport),
		libp2p.Peerstore(peerStore),
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", wg.config.Port), fmt.Sprintf("/ip6/::/tcp/%d", wg.config.Port)))
	if err != nil {
		wg.backgroundCancel()
		peerStore.Close()
		return nil, fmt.Errorf("failed to create libp2p host: %w", err)
	}

	psk.Write([]byte("wireguard_p2p"))
	wg.wgPsk, err = wgtypes.NewKey(psk.Sum(nil))
	if err != nil {
		wg.backgroundCancel()
		wg.host.Close()
		peerStore.Close()
		return nil, fmt.Errorf("failed to create WireGuard pre-shared key: %w", err)
	}

	dhtDataStore, err := leveldb.NewDatastore(wg.config.DhtDataPath, nil)
	if err != nil {
		wg.backgroundCancel()
		wg.host.Close()
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
		return nil, fmt.Errorf("failed to create DHT: %w", err)
	}

	wg.pubsub, err = pubsub.NewGossipSub(wg.backgroundCtx, wg.host)
	if err != nil {
		wg.backgroundCancel()
		wg.dht.Close()
		wg.host.Close()
		return nil, fmt.Errorf("failed to create PubSub: %w", err)
	}

	wg.peersTopic, err = wg.pubsub.Join(PeerUpdateTopic)
	if err != nil {
		wg.backgroundCancel()
		wg.dht.Close()
		wg.host.Close()
		return nil, fmt.Errorf("failed to join PubSub topic %s: %w", PeerUpdateTopic, err)
	}

	wg.peerSub, err = wg.peersTopic.Subscribe()
	if err != nil {
		wg.backgroundCancel()
		wg.peersTopic.Close()
		wg.dht.Close()
		wg.host.Close()
		return nil, fmt.Errorf("failed to subscribe to PubSub topic %s: %w", PeerUpdateTopic, err)
	}

	wg.wgClient, err = wgctrl.New()
	if err != nil {
		wg.backgroundCancel()
		wg.peersTopic.Close()
		wg.peerSub.Cancel()
		wg.dht.Close()
		wg.host.Close()
		return nil, fmt.Errorf("failed to create WireGuard client: %w", err)
	}

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
	wgLink := &netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{Name: wg.config.WireguardInterface},
		LinkType:  "wireguard",
	}

	if runtime.GOOS == "linux" {
		if err := netlink.LinkAdd(wgLink); err != nil {
			panic(fmt.Sprintf("Failed to create WireGuard interface: %v", err))
		}

		if err := netlink.AddrAdd(wgLink, &netlink.Addr{
			IPNet: &net.IPNet{
				IP:   net.ParseIP(wg.config.WireguardIp),
				Mask: net.CIDRMask(32, 32),
			},
		}); err != nil {
			panic(fmt.Sprintf("Failed to add IP address to WireGuard interface: %v", err))
		}

		if err := netlink.LinkSetUp(wgLink); err != nil {
			panic(fmt.Sprintf("Failed to bring up WireGuard interface: %v", err))
		}
	}

	// Kad-DHT Bootstrap
	go func() {
		if err := wg.dht.Bootstrap(wg.backgroundCtx); err != nil {
			panic(err)
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

				fmt.Printf("Error receiving message: %v\n", err)
				continue
			}

			if msg == nil {
				fmt.Println("Received nil message, skipping")
				continue
			}

			if msg.GetFrom() == wg.host.ID() {
				continue // skip messages from self
			}

			wgPeerData := strings.Split(string(msg.Data), "@")
			if len(wgPeerData) != 3 {
				fmt.Printf("Invalid WireGuard peer data format: %s\n", string(msg.Data))
				continue
			}

			peerPublicIp := net.ParseIP(wgPeerData[0])
			if peerPublicIp == nil {
				fmt.Printf("Invalid IP address: %s\n", wgPeerData[0])
				continue
			}

			peerInterfaceIp := net.ParseIP(wgPeerData[1])
			if peerInterfaceIp == nil {
				fmt.Printf("Invalid interface IP address: %s\n", wgPeerData[1])
				continue
			}

			wg.wgPeersMutex.Lock()
			if peer, ok := wg.wgPeers[msg.GetFrom().String()]; ok {
				if peer.PublicIp.Equal(peerPublicIp) && peer.InterfaceIP.Equal(peerInterfaceIp) && peer.PublicKey == wgPeerData[2] {
					wg.wgPeersMutex.Unlock()
					continue
				}
			}

			wg.wgPeers[msg.GetFrom().String()] = wgPeer{
				PublicIp:    peerPublicIp,
				InterfaceIP: peerInterfaceIp,
				PublicKey:   wgPeerData[2],
			}

			wg.wgPeersMutex.Unlock()

			wg.wgPeersMutex.RLock()
			peers := make([]wgtypes.PeerConfig, 0, len(wg.wgPeers))
			for _, peer := range wg.wgPeers {
				peerPublicKey, err := wgtypes.ParseKey(wgPeerData[2])
				if err != nil {
					fmt.Printf("Invalid public key: %v\n", err)
					continue
				}

				peers = append(peers, wgtypes.PeerConfig{
					PublicKey: peerPublicKey,
					AllowedIPs: []net.IPNet{
						{
							IP:   peer.InterfaceIP,
							Mask: net.CIDRMask(32, 32),
						},
					},
					Endpoint: &net.UDPAddr{
						IP:   peer.PublicIp,
						Port: wg.config.WireguardPort,
					},
					PresharedKey: &wg.wgPsk,
				})

				if runtime.GOOS == "linux" {
					err = netlink.RouteAdd(&netlink.Route{
						Dst: &net.IPNet{
							IP:   peer.InterfaceIP,
							Mask: net.CIDRMask(32, 32),
						},
						LinkIndex: wgLink.Attrs().Index,
						Scope:     netlink.SCOPE_LINK,
					})
					if err != nil {
						fmt.Printf("Error adding route for WireGuard peer: %v\n", err)
						continue
					}
				}
			}
			wg.wgPeersMutex.RUnlock()

			err = wg.wgClient.ConfigureDevice(wg.config.WireguardInterface, wgtypes.Config{
				PrivateKey:   &wg.wgPrivateKey,
				ListenPort:   wireguardPort,
				ReplacePeers: true,
				Peers:        peers,
			})
			if err != nil {
				fmt.Printf("Error configuring WireGuard device: %v\n", err)
				continue
			}
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
					c, ca := context.WithTimeout(wg.backgroundCtx, 3*time.Second)
					if err := wg.host.Connect(c, addrInfo); err != nil {
						ca()
						fmt.Printf("Error connecting to peer %s: %v\n", peer, err)
						continue
					}
					ca()
					break
				}
			}

			wg.peersTopic.Publish(wg.backgroundCtx, []byte(string(wg.publicIpAddress.String())+"@"+wg.config.WireguardIp+"@"+wg.wgPrivateKey.PublicKey().String()))

			time.Sleep(1 * time.Minute)
		}
	}()

	return nil
}

func (wg *WireguardP2P) Close() error {
	wg.backgroundCancel()
	wg.peersTopic.Close()
	wg.dht.Close()
	wg.host.Close()

	if err := wg.dht.Close(); err != nil {
		return fmt.Errorf("failed to close DHT: %w", err)
	}

	if err := wg.host.Close(); err != nil {
		return fmt.Errorf("failed to close host: %w", err)
	}

	if runtime.GOOS == "linux" {
		wgLink, err := netlink.LinkByName(wg.config.WireguardInterface)
		if err != nil {
			return fmt.Errorf("failed to get WireGuard interface: %w", err)
		}

		if err := netlink.LinkDel(wgLink); err != nil {
			return fmt.Errorf("failed to delete WireGuard interface: %w", err)
		}
	}

	if err := wg.wgClient.Close(); err != nil {
		return fmt.Errorf("failed to close WireGuard client: %w", err)
	}

	return nil
}
