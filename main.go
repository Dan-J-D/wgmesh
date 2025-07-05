package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"gopkg.in/yaml.v3"
)

var (
	port               = flag.Int("port", 37950, "Port to listen on for libp2p connections")
	dataPath           = flag.String("data-path", "data", "Path to store data (e.g., datastore, DHT records, config, etc.)")
	publicIp           = flag.String("public-ip", "", "Public IP address for WireGuard interface (required)")
	wireguardIp        = flag.String("wireguard-ip", "10.0.0.1", "IP address for WireGuard interface")
	wireguardPort      = flag.Int("wireguard-port", 51820, "WireGuard port to listen on")
	wireguardInterface = flag.String("wireguard-interface", "wg0", "WireGuard interface name")
	preSharedKey       = flag.String("pre-shared-key", "", "Pre-shared key for private network (optional)")

	debug = flag.Bool("debug", false, "Enable debug logging ")
)

func main() {
	flag.Parse()

	if *debug {
		log.SetDebugLogging()
	}

	dataPathAbs, err := filepath.Abs(*dataPath)
	if err != nil {
		panic(fmt.Sprintf("Failed to get absolute path for data path %s: %v", *dataPath, err))
	}

	err = os.MkdirAll(dataPathAbs, 0755)
	if err != nil {
		panic(fmt.Sprintf("Failed to create data path %s: %v", dataPathAbs, err))
	}
	var config Config
	if info, err := os.Stat(filepath.Join(dataPathAbs, "config.yaml")); err == nil && !info.IsDir() {
		data, err := os.ReadFile(filepath.Join(dataPathAbs, "config.yaml"))
		if err != nil {
			panic(fmt.Sprintf("Failed to read config file: %v", err))
		}

		if err := yaml.Unmarshal(data, &config); err != nil {
			panic(fmt.Sprintf("Failed to unmarshal config file: %v", err))
		}

		config.DataPath = dataPathAbs
	} else {
		config = Config{
			DataPath: dataPathAbs,

			PublicIp:           *publicIp,
			Port:               *port,
			WireguardIp:        *wireguardIp,
			WireguardPort:      *wireguardPort,
			WireguardInterface: *wireguardInterface,

			PreSharedKey:           *preSharedKey,
			WireguardPrivateKey:    "", // will be generated if not provided
			PeerIdentityPrivateKey: "", // will be generated if not provided
		}
	}

	wg, err := NewWireguardP2P(config)
	if err != nil {
		panic(fmt.Sprintf("Failed to create WireGuard P2P instance: %v", err))
	}
	defer wg.Close()

	{
		config := wg.GetConfig()
		configData, err := yaml.Marshal(config)
		if err != nil {
			panic(fmt.Sprintf("Failed to marshal config: %v", err))
		}

		if err := os.WriteFile(filepath.Join(dataPathAbs, "config.yaml"), configData, 0644); err != nil {
			panic(fmt.Sprintf("Failed to write config file: %v", err))
		}
	}

	connectStr, err := json.Marshal(wg.GetAddrs())
	if err != nil {
		panic(fmt.Sprintf("Failed to marshal connect string: %v", err))
	}
	fmt.Println("Connect Addrs: ", string(connectStr))

	err = wg.Start()
	if err != nil {
		panic(fmt.Sprintf("Failed to start WireGuard P2P instance: %v", err))
	}

	for {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			input := scanner.Text()

			if input == "" {
				continue
			}

			if len(input) > 1 && input[0] == '/' {
				inputSplit := strings.Split(input[1:], " ")
				if len(inputSplit) == 0 {
					fmt.Println("Invalid command, please try again.")
					continue
				}

				switch inputSplit[0] {
				case "connect":
					if len(inputSplit) < 2 {
						fmt.Println("Usage: /connect <connect-string>")
						continue
					}

					connectStr := strings.Join(inputSplit[1:], " ")
					addrs := []string{}
					err := json.Unmarshal([]byte(connectStr), &addrs)
					if err != nil {
						fmt.Printf("Invalid connect string: %v\n", err)
						continue
					}

					connectAddrs := peer.AddrInfo{
						ID:    "",
						Addrs: make([]ma.Multiaddr, 0, len(addrs)),
					}

					for _, addrStr := range addrs {
						addr, err := ma.NewMultiaddr(addrStr)
						if err != nil {
							fmt.Printf("Invalid multi-address: %v\n", err)
							continue
						}

						ma, id := peer.SplitAddr(addr)
						if ma != nil {
							if connectAddrs.ID == "" {
								connectAddrs.ID = id
							} else if connectAddrs.ID != id {
								fmt.Printf("Peer ID mismatch: expected %s, got %s\n", connectAddrs.ID, id)
								continue
							}

							connectAddrs.Addrs = append(connectAddrs.Addrs, ma)
						}
					}

					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					if err := wg.GetHost().Connect(ctx, connectAddrs); err != nil {
						cancel()
						fmt.Printf("Error connecting to peer: %v\n", err)
						continue
					}
					cancel()

					fmt.Printf("Connected to peer: %s\n", connectAddrs.ID)
				case "peers":
					peers := wg.GetHost().Network().Peers()
					if len(peers) == 0 {
						fmt.Println("No connected peers.")
					} else {
						fmt.Println("Connected peers:")
						for _, p := range peers {
							fmt.Printf("- %s\n", p)
						}
					}
				case "find-peer":
					if len(inputSplit) < 2 {
						fmt.Println("Usage: /find-peer <peer-id>")
						continue
					}

					peerID, err := peer.Decode(inputSplit[1])
					if err != nil {
						fmt.Printf("Invalid peer ID: %v\n", err)
						continue
					}

					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					addrInfo, err := wg.GetDHT().FindPeer(ctx, peerID)
					cancel()
					if err != nil {
						fmt.Printf("Error finding peer: %v\n", err)
						continue
					}

					fmt.Printf("Found peer: %s with addresses: %v\n", addrInfo.ID, addrInfo.Addrs)
				case "exit":
					fmt.Println("Exiting...")
					return
				default:
					fmt.Printf("Unknown command: `%s`\n", inputSplit[0])
				}

				continue
			}
		}

		if err := scanner.Err(); err != nil {
			fmt.Printf("Error reading input: %v\n", err)
		}
	}
}
