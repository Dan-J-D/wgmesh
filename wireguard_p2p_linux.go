//go:build linux
// +build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

func writeWireGuardInterface(_ string, config wireguardConfig) error {
	return os.WriteFile(filepath.Join("/etc/wireguard", config.Interface+".conf"), []byte(config.String()), 0600)
}

func deleteWireGuardInterface(interfaceName, _ string) error {
	return os.Remove(filepath.Join("/etc/wireguard", interfaceName+".conf"))
}

func installWireguardInterface(interfaceName, _ string) error {
	return exec.Command("wg-quick", "up", interfaceName).Run()
}

func uninstallWireguardInterface(interfaceName string) error {
	return exec.Command("wg-quick", "down", interfaceName).Run()
}

func syncWireguardInterface(interfaceName, _ string) error {
	if err := uninstallWireguardInterface(interfaceName); err != nil {
		return err
	}
	for i := 0; ; i++ {
		err := installWireguardInterface(interfaceName, "")
		if err == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
		if i >= 10 {
			return err
		}
	}
}
