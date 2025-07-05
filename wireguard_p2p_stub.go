//go:build !windows && !linux
// +build !windows,!linux

package main

import (
	"errors"
)

func writeWireGuardInterface(_ string, _ wireguardConfig) error {
	return errors.New("WireGuard interface management is not supported on this platform")
}

func deleteWireGuardInterface(interfaceName, configPath string) error {
	return errors.New("WireGuard interface management is not supported on this platform")
}

func installWireguardInterface(_, _ string) error {
	return errors.New("WireGuard interface management is not supported on this platform")
}

func uninstallWireguardInterface(_ string) error {
	return errors.New("WireGuard interface management is not supported on this platform")
}

func syncWireguardInterface(_, _ string) error {
	return errors.New("WireGuard interface management is not supported on this platform")
}
