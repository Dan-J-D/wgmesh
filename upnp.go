package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/huin/goupnp/dcps/internetgateway1"
	"github.com/huin/goupnp/dcps/internetgateway2"
	"golang.org/x/exp/slog"
	"golang.org/x/sync/errgroup"
)

const (
	DefaultLeaseDurationSeconds = 30 * 60 // Default lease duration for port mappings
)

var ErrUpnpClosed = errors.New("UPnP closed")

type routerClient interface {
	AddPortMapping(
		NewRemoteHost string,
		NewExternalPort uint16,
		NewProtocol string,
		NewInternalPort uint16,
		NewInternalClient string,
		NewEnabled bool,
		NewPortMappingDescription string,
		NewLeaseDuration uint32,
	) (err error)

	GetExternalIPAddress() (
		NewExternalIPAddress string,
		err error,
	)

	LocalAddr() net.IP
}

type upnpPortMapping struct {
	ClientIdxs []uint32

	ExternalPort uint16
	InternalPort uint16
	Protocol     string // "TCP" or "UDP"
	Description  string
}

type upnp struct {
	clients []routerClient

	portMapIdx     atomic.Uint32
	portsMapped    map[uint32]upnpPortMapping
	portsMappedMtx sync.RWMutex
	closeCh        chan struct{}
}

func NewUpnp() (*upnp, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

	tasks, _ := errgroup.WithContext(ctx)

	var ip1Clients []*internetgateway2.WANIPConnection1
	tasks.Go(func() error {
		var err error
		ip1Clients, _, err = internetgateway2.NewWANIPConnection1Clients()
		return err
	})
	var ip2Clients []*internetgateway2.WANIPConnection2
	tasks.Go(func() error {
		var err error
		ip2Clients, _, err = internetgateway2.NewWANIPConnection2Clients()
		return err
	})
	var ppp1Clients []*internetgateway2.WANPPPConnection1
	tasks.Go(func() error {
		var err error
		ppp1Clients, _, err = internetgateway2.NewWANPPPConnection1Clients()
		return err
	})
	var ig2ip1Clients []*internetgateway1.WANIPConnection1
	tasks.Go(func() error {
		var err error
		ig2ip1Clients, _, err = internetgateway1.NewWANIPConnection1Clients()
		return err
	})
	var ig2ppp1Clients []*internetgateway1.WANPPPConnection1
	tasks.Go(func() error {
		var err error
		ig2ppp1Clients, _, err = internetgateway1.NewWANPPPConnection1Clients()
		return err
	})

	if err := tasks.Wait(); err != nil {
		cancel()
		slog.Error("Failed to initialize UPnP clients", "error", err)
		return nil, err
	}
	cancel()

	if len(ip1Clients) == 0 && len(ip2Clients) == 0 && len(ppp1Clients) == 0 && len(ig2ip1Clients) == 0 && len(ig2ppp1Clients) == 0 {
		slog.Warn("No UPnP clients found", "ip1Clients", len(ip1Clients), "ip2Clients", len(ip2Clients), "ppp1Clients", len(ppp1Clients), "ig2ip1Clients", len(ig2ip1Clients), "ig2ppp1Clients", len(ig2ppp1Clients))
		return nil, errors.New("no UPnP clients found")
	}

	upnp := new(upnp)
	upnp.clients = make([]routerClient, 0, len(ip1Clients)+len(ip2Clients)+len(ppp1Clients))
	upnp.portMapIdx = atomic.Uint32{}
	upnp.portMapIdx.Add(1) // Start from 1 to avoid confusion with zero index
	upnp.portsMapped = make(map[uint32]upnpPortMapping, 0)
	upnp.portsMappedMtx = sync.RWMutex{}
	upnp.closeCh = make(chan struct{})

	for _, client := range ip1Clients {
		if client != nil {
			upnp.clients = append(upnp.clients, client)
		}
	}

	for _, client := range ip2Clients {
		if client != nil {
			upnp.clients = append(upnp.clients, client)
		}
	}

	for _, client := range ppp1Clients {
		if client != nil {
			upnp.clients = append(upnp.clients, client)
		}
	}

	for _, client := range ig2ip1Clients {
		if client != nil {
			upnp.clients = append(upnp.clients, client)
		}
	}

	for _, client := range ig2ppp1Clients {
		if client != nil {
			upnp.clients = append(upnp.clients, client)
		}
	}

	return upnp, nil
}

func (u *upnp) Close() error {
	close(u.closeCh)
	u.portsMappedMtx.Lock()
	defer u.portsMappedMtx.Unlock()

	for port, mapping := range u.portsMapped {
		for _, clientIdx := range mapping.ClientIdxs {
			if int(clientIdx) >= len(u.clients) || u.clients[clientIdx] == nil {
				continue
			}

			client := u.clients[clientIdx]
			err := client.AddPortMapping(
				"",
				mapping.ExternalPort,
				mapping.Protocol,
				mapping.InternalPort,
				client.LocalAddr().String(),
				false, // Disable the port mapping
				mapping.Description,
				DefaultLeaseDurationSeconds,
			)
			if err != nil {
				slog.Error("Failed to remove port mapping", "error", err, "portMapIdx", port)
			} else {
				slog.Info("Removed port mapping", "portMapIdx", port, "externalPort", mapping.ExternalPort, "protocol", mapping.Protocol)
			}
		}
		delete(u.portsMapped, port)
	}
	return nil
}

func (u *upnp) Run() error {
	select {
	case <-u.closeCh:
		return ErrUpnpClosed
	case <-time.After(10 * time.Minute):
		u.portsMappedMtx.Lock()
		for _, mapping := range u.portsMapped {
			for _, clientIdx := range mapping.ClientIdxs {
				if int(clientIdx) >= len(u.clients) || u.clients[clientIdx] == nil {
					continue
				}

				client := u.clients[clientIdx]
				err := client.AddPortMapping(
					"",
					mapping.ExternalPort,
					mapping.Protocol,
					mapping.InternalPort,
					client.LocalAddr().String(),
					true, // Re-enable the port mapping
					mapping.Description,
					DefaultLeaseDurationSeconds,
				)
				if err != nil {
					slog.Error("Failed to re-enable port mapping", "error", err, "portMapIdx", mapping.ClientIdxs)
				} else {
					slog.Info("Re-enabled port mapping", "portMapIdx", mapping.ClientIdxs, "externalPort", mapping.ExternalPort, "protocol", mapping.Protocol)
				}
			}
		}
		u.portsMappedMtx.Unlock()
	}
	return nil
}

func (u *upnp) AddPortMapping(
	externalPort uint16,
	internalPort uint16,
	protocol string, // "TCP" or "UDP"
	description string,
) (uint32, error) {
	u.portsMappedMtx.Lock()
	defer u.portsMappedMtx.Unlock()
	if len(u.clients) == 0 {
		slog.Error("No UPnP clients available for port mapping", "externalPort", externalPort, "protocol", protocol)
		return 0, errors.New("no UPnP clients available")
	}

	clientIdxs := []uint32{}
	for i, client := range u.clients {
		if client == nil {
			continue
		}

		err := client.AddPortMapping(
			"",
			externalPort,
			protocol,
			internalPort,
			client.LocalAddr().String(),
			true,
			description,
			DefaultLeaseDurationSeconds,
		)
		if err != nil {
			slog.Error("Failed to add port mapping", "error", err, "clientIdx", i, "externalPort", externalPort, "protocol", protocol)
			return 0, err
		}

		slog.Info("Adding port mapping", "clientIdx", i, "externalPort", externalPort, "internalPort", internalPort, "protocol", protocol)
		clientIdxs = append(clientIdxs, uint32(i))
	}

	idx := u.portMapIdx.Add(1)
	u.portsMapped[idx] = upnpPortMapping{
		ClientIdxs: clientIdxs,

		ExternalPort: externalPort,
		InternalPort: internalPort,
		Protocol:     protocol,
		Description:  description,
	}
	return idx, nil
}

func (u *upnp) RemovePortMapping(portMapIdx uint32) error {
	u.portsMappedMtx.Lock()
	defer u.portsMappedMtx.Unlock()
	if len(u.clients) == 0 {
		slog.Error("No UPnP clients available for removing port mapping", "portMapIdx", portMapIdx)
		return errors.New("no UPnP clients available")
	}

	mapping, exists := u.portsMapped[portMapIdx]
	if !exists {
		slog.Error("Port mapping not found", "portMapIdx", portMapIdx)
		return errors.New("port mapping not found")
	}

	for _, clientIdx := range mapping.ClientIdxs {
		if int(clientIdx) >= len(u.clients) || u.clients[clientIdx] == nil {
			continue
		}

		client := u.clients[clientIdx]
		err := client.AddPortMapping(
			"",
			mapping.ExternalPort,
			mapping.Protocol,
			mapping.InternalPort,
			client.LocalAddr().String(),
			false, // Disable the port mapping
			mapping.Description,
			DefaultLeaseDurationSeconds,
		)
		if err != nil {
			slog.Error("Failed to remove port mapping", "error", err, "portMapIdx", portMapIdx)
			continue
		}
	}

	delete(u.portsMapped, portMapIdx)
	return nil
}

func (u *upnp) GetExternalIPAddresses() ([]string, error) {
	addresses := make([]string, 0, len(u.clients))
	for _, client := range u.clients {
		if client == nil {
			continue
		}

		ip, err := client.GetExternalIPAddress()
		if err != nil {
			slog.Error("Failed to get external IP address", "error", err, "client", client)
			return nil, err
		}
		addresses = append(addresses, ip)
	}
	return addresses, nil
}
