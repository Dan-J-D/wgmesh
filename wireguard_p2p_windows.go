//go:build windows
// +build windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func writeWireGuardInterface(configPath string, config wireguardConfig) error {
	return os.WriteFile(filepath.Join(configPath, config.Interface+".conf"), []byte(config.String()), 0600)
}

func deleteWireGuardInterface(interfaceName, configPath string) error {
	return os.Remove(filepath.Join(configPath, interfaceName+".conf"))
}

func installWireguardInterface(interfaceName, configPath string) error {
	if strings.HasSuffix(configPath, ".conf") {
		return errors.New("Config file must be a .conf file")
	}

	return exec.Command("wireguard", "/installtunnelservice", filepath.Join(configPath, interfaceName+".conf")).Run()
}

func uninstallWireguardInterface(interfaceName string) error {
	return exec.Command("wireguard", "/uninstalltunnelservice", interfaceName).Run()
}

func syncWireguardInterface(interfaceName, configPath string) error {
	if err := uninstallWireguardInterface(interfaceName); err != nil {
		return err
	}

	for i := 0; ; i++ {
		err := installWireguardInterface(interfaceName, configPath)
		if err == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
		if i >= 10 {
			return err
		}
	}
}
