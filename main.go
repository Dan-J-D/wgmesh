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
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ipfs/go-log/v2"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
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

	logLevel  = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	logFile   = flag.String("log-file", "", "Log file path (optional)")
	logStdout = flag.Bool("log-stdout", true, "Enable logging to stdout")

	debugLibp2p = flag.Bool("debug-libp2p", false, "Enable debug logging for libp2p")
)

type multiHandler struct {
	handlers []slog.Handler
}

func (m *multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range m.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (m *multiHandler) Handle(ctx context.Context, r slog.Record) error {
	var err error
	for _, h := range m.handlers {
		if h.Enabled(ctx, r.Level) {
			e := h.Handle(ctx, r)
			if e != nil && err == nil {
				err = e
			}
		}
	}
	return err
}

func (m *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newHandlers := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		newHandlers[i] = h.WithAttrs(attrs)
	}
	return &multiHandler{handlers: newHandlers}
}

func (m *multiHandler) WithGroup(name string) slog.Handler {
	newHandlers := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		newHandlers[i] = h.WithGroup(name)
	}
	return &multiHandler{handlers: newHandlers}
}

func main() {
	flag.Parse()

	if *debugLibp2p {
		log.SetDebugLogging()
	}

	if *logLevel != "" {
		// setup slog logger
		var lvl slog.Level
		switch *logLevel {
		case "debug":
			lvl = slog.LevelDebug
		case "info":
			lvl = slog.LevelInfo
		case "warn":
			lvl = slog.LevelWarn
		case "error":
			lvl = slog.LevelError
		default:
			panic(fmt.Sprintf("Invalid log level: %s", *logLevel))
		}

		var handlers []slog.Handler
		if *logFile != "" {
			file, err := os.OpenFile(*logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				panic(fmt.Sprintf("Failed to open log file %s: %v", *logFile, err))
			}
			defer file.Close()

			fileHandler := slog.NewJSONHandler(file, &slog.HandlerOptions{
				Level: lvl,
			})
			if err != nil {
				panic(fmt.Sprintf("Failed to create file logger: %v", err))
			}
			handlers = append(handlers, fileHandler)
		}

		if *logStdout {
			stdoutHandler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
				Level: lvl,
			})
			handlers = append(handlers, stdoutHandler)
		}

		if len(handlers) > 0 {
			slog.SetDefault(slog.New(&multiHandler{handlers: handlers}))
		}
	}

	dataPathAbs, err := filepath.Abs(*dataPath)
	if err != nil {
		slog.Error("Failed to get absolute path for data path", "dataPath", *dataPath, "error", err)
		panic(fmt.Sprintf("Failed to get absolute path for data path %s: %v", *dataPath, err))
	}

	err = os.MkdirAll(dataPathAbs, 0755)
	if err != nil {
		slog.Error("Failed to create data path", "dataPath", dataPathAbs, "error", err)
		panic(fmt.Sprintf("Failed to create data path %s: %v", dataPathAbs, err))
	}
	var config Config
	if info, err := os.Stat(filepath.Join(dataPathAbs, "config.yaml")); err == nil && !info.IsDir() {
		data, err := os.ReadFile(filepath.Join(dataPathAbs, "config.yaml"))
		if err != nil {
			slog.Error("Failed to read config file", "file", filepath.Join(dataPathAbs, "config.yaml"), "error", err)
			panic(fmt.Sprintf("Failed to read config file: %v", err))
		}

		if err := yaml.Unmarshal(data, &config); err != nil {
			slog.Error("Failed to unmarshal config file", "file", filepath.Join(dataPathAbs, "config.yaml"), "error", err)
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
		slog.Error("Failed to create WireGuard P2P instance", "error", err)
		panic(fmt.Sprintf("Failed to create WireGuard P2P instance: %v", err))
	}
	defer wg.Close()

	{
		config := wg.GetConfig()
		configData, err := yaml.Marshal(config)
		if err != nil {
			slog.Error("Failed to marshal config", "error", err)
			panic(fmt.Sprintf("Failed to marshal config: %v", err))
		}

		if err := os.WriteFile(filepath.Join(dataPathAbs, "config.yaml"), configData, 0644); err != nil {
			slog.Error("Failed to write config file", "file", filepath.Join(dataPathAbs, "config.yaml"), "error", err)
			panic(fmt.Sprintf("Failed to write config file: %v", err))
		}
	}

	err = wg.Start()
	if err != nil {
		slog.Error("Failed to start WireGuard P2P instance", "error", err)
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
				case "connect-string":
					connectStr, err := json.Marshal(wg.GetAddrs())
					if err != nil {
						fmt.Println("Failed to marshal connect string: %v", err)
						continue
					}
					fmt.Println("Connect Addrs: ", string(connectStr))
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

					wg.GetHost().Peerstore().AddAddrs(connectAddrs.ID, connectAddrs.Addrs, peerstore.PermanentAddrTTL)
					slog.Info("Connected to peer", "peerID", connectAddrs.ID, "addrs", connectAddrs.Addrs)
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
				case "exit":
					slog.Info("Exiting...")
					return
				default:
					fmt.Printf("Unknown command: `%s`\n", inputSplit[0])
				}

				continue
			}
		}

		if err := scanner.Err(); err != nil {
			slog.Error("Error reading input", "error", err)
		}
	}
}
